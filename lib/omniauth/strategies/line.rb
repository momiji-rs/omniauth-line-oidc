# frozen_string_literal: true

require 'omniauth-oauth2'
require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'

module OmniAuth
  module Strategies
    # LINE Login v2.1.
    #
    # The user is identified by the profile API, called with the access token
    # this sign-in was just issued. The ID token adds claims the profile API
    # does not have (the email above all). Its claims are used only after
    # LINE's verify endpoint has accepted the token, together with the nonce
    # this strategy sent. A token LINE rejects fails the sign-in; a verify
    # endpoint that cannot be reached leaves the sign-in working without the
    # claims.
    class Line < OmniAuth::Strategies::OAuth2
      VERIFY_URL = 'https://api.line.me/oauth2/v2.1/verify'
      SESSION_KEY = 'omniauth.line'
      # Sign-ins a browser session can have under way at once, each with its
      # own nonce; the oldest is dropped beyond this.
      MAX_PENDING_SIGN_INS = 5

      # Failures that say nothing about the token: LINE was not reached, or
      # did not answer.
      VERIFY_UNREACHABLE = [
        ::Timeout::Error, ::SystemCallError, ::SocketError, ::IOError, ::OpenSSL::SSL::SSLError
      ].freeze

      option :name, 'line'
      option :scope, 'profile openid'

      # LINE supports PKCE with S256 only, which is what omniauth-oauth2 sends
      # with `pkce: true`. It is off unless asked for because omniauth-oauth2
      # keeps a 128-character verifier in the session for each of the last
      # five sign-ins, which a 4 KB cookie session has no room for.
      option :pkce, false

      # omniauth-oauth2 only forwards options named here to the authorize
      # URL; anything else set on the strategy is silently dropped. `nonce` is
      # absent on purpose: a nonce configured once would be the same for every
      # sign-in, so the strategy always generates its own.
      option :authorize_options, %i[
        scope state prompt max_age ui_locales bot_prompt
        initial_amr_display switch_amr disable_auto_login
        disable_ios_auto_login
      ]

      # The verify call runs inside the user-facing callback request, so a
      # slow LINE API must fail fast rather than hold the login hostage.
      DEFAULT_VERIFY_TIMEOUTS = { open_timeout: 5, read_timeout: 10 }.freeze
      option :verify_options, DEFAULT_VERIFY_TIMEOUTS.dup

      # Authorization lives on access.line.me while every API call
      # (token exchange, profile, verify) lives on api.line.me.
      option :client_options, {
        site: 'https://api.line.me',
        authorize_url: 'https://access.line.me/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token',
        auth_scheme: :request_body
      }

      uid do
        ensure_id_token_is_for_this_user!
        raw_info['userId']
      end

      info do
        {
          name: raw_info['displayName'],
          image: raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email: email
        }
      end

      extra do
        hash = { raw_info: raw_info }
        hash[:id_token] = id_token if id_token
        hash[:id_token_claims] = id_token_claims unless id_token_claims.empty?
        hash[:friendship_status_changed] = friendship_status_changed unless friendship_status_changed.nil?
        hash
      end

      # A nonce ties the ID token to this sign-in: it is sent with the
      # authorization request, LINE copies it into the ID token, and the
      # verify call later states which nonce the token must carry.
      def authorize_params
        super.tap do |params|
          next unless openid_scope?(params[:scope])

          params[:nonce] = issue_nonce(params[:state].to_s)
        end
      end

      # The nonce is taken before anything can fail, so a callback that is
      # refused or carries an error leaves none behind.
      def callback_phase
        @nonce = take_nonce
        super
      end

      # LINE returns the email claim only inside the ID token (email scope),
      # never from the profile endpoint.
      def email
        id_token_claims['email']
      end

      # The ID token's claims as LINE's verify endpoint returned them, or an
      # empty hash when there is no ID token or LINE could not be asked.
      def id_token_claims
        @id_token_claims ||= id_token ? verified_claims : {}
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= fetch_profile
      end

      # `callback_url` is the option name omniauth-line 0.1.0 used.
      def callback_url
        options[:redirect_uri] || options[:callback_url] || (full_host + script_name + callback_path)
      end

      private

      def id_token
        access_token['id_token']
      end

      # Set by LINE on the callback only when `bot_prompt` was requested.
      def friendship_status_changed
        value = request.params['friendship_status_changed']
        value.nil? ? nil : value.to_s == 'true'
      end

      def openid_scope?(scope)
        scope.to_s.split(/[\s,]+/).include?('openid')
      end

      def fetch_profile
        profile = parse_json(access_token.get('v2/profile').body)
        return profile if profile.is_a?(Hash) && profile['userId']

        raise CallbackError.new(:invalid_credentials, 'the profile response names no user')
      end

      # The profile comes from the access token and the claims from the ID
      # token; both were issued by the same token response, so they name the
      # same user unless something is badly wrong.
      def ensure_id_token_is_for_this_user!
        subject = id_token_claims['sub']
        return if subject.nil? || subject == raw_info['userId']

        raise CallbackError.new(:invalid_credentials, 'the ID token and the profile name different users')
      end

      def verified_claims
        response = verify_id_token
        payload = parse_json(response.body)

        if response.is_a?(Net::HTTPSuccess)
          return payload if payload.is_a?(Hash) && payload['sub']

          log :warn, 'ID token verify returned no claims'
        elsif response.is_a?(Net::HTTPBadRequest)
          # LINE's answer for a token that fails a check, the nonce included.
          description = payload['error_description'] || payload['error'] if payload.is_a?(Hash)
          raise CallbackError.new(:invalid_credentials, "LINE rejected the ID token: #{description}")
        else
          log :warn, "ID token verify unavailable (HTTP #{response.code})"
        end
        {}
      rescue *VERIFY_UNREACHABLE => e
        log :warn, "ID token verify could not be reached (#{e.class})"
        {}
      end

      def verify_id_token
        uri = URI(VERIFY_URL)
        request = Net::HTTP::Post.new(uri)
        form = { id_token: id_token, client_id: client.id }
        form[:nonce] = @nonce if @nonce
        request.set_form_data(form)
        timeouts = options.verify_options || {}
        Net::HTTP.start(uri.host, uri.port,
                        use_ssl: true,
                        open_timeout: timeouts[:open_timeout] || DEFAULT_VERIFY_TIMEOUTS[:open_timeout],
                        read_timeout: timeouts[:read_timeout] || DEFAULT_VERIFY_TIMEOUTS[:read_timeout]) do |http|
          http.request(request)
        end
      end

      def parse_json(body)
        JSON.parse(body.to_s)
      rescue JSON::ParserError
        nil
      end

      # The session is often a 4 KB cookie, so it holds one secret and a short
      # fingerprint of each sign-in under way rather than a nonce per sign-in.
      # A sign-in's nonce is derived from the secret and its `state`, which
      # gives two sign-ins started in one browser session each their own.
      def issue_nonce(state)
        secret = stored_secret || SecureRandom.hex(16)
        pending = (stored_pending - [fingerprint(secret, state)]) << fingerprint(secret, state)
        session[SESSION_KEY] = { 'secret' => secret, 'pending' => pending.last(MAX_PENDING_SIGN_INS) }
        nonce_for(secret, state)
      end

      # nil when this callback's session did not start the sign-in; the
      # verify call then checks everything about the token except the nonce.
      def take_nonce
        secret = stored_secret
        state = request.params['state'].to_s
        pending = stored_pending
        return unless secret && pending.delete(fingerprint(secret, state))

        session[SESSION_KEY] = { 'secret' => secret, 'pending' => pending }
        nonce_for(secret, state)
      end

      def nonce_for(secret, state)
        OpenSSL::HMAC.hexdigest('SHA256', secret, "nonce:#{state}")[0, 32]
      end

      def fingerprint(secret, state)
        OpenSSL::HMAC.hexdigest('SHA256', secret, "state:#{state}")[0, 8]
      end

      def stored_secret
        secret = stored['secret']
        secret if secret.is_a?(String) && !secret.empty?
      end

      def stored_pending
        pending = stored['pending']
        pending.is_a?(Array) ? pending.dup : []
      end

      def stored
        value = session[SESSION_KEY]
        value.is_a?(Hash) ? value : {}
      end
    end
  end
end
