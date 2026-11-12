# frozen_string_literal: true

require 'spec_helper'
require 'rack/session'

# The strategy as Rack middleware, through both phases, with one browser
# session carried by the cookie jar and LINE stubbed at the HTTP boundary.
describe OmniAuth::Strategies::Line, 'sign-in flow' do
  let(:seen) { {} }
  let(:strategy_options) { {} }
  let(:id_token) { 'header.payload.signature' }

  let(:app) do
    seen_by_app = seen
    options = strategy_options

    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 's' * 64
      use OmniAuth::Strategies::Line, 'channel-id', 'channel-secret', options
      run lambda { |env|
        seen_by_app[:auth] = env['omniauth.auth']
        seen_by_app[:nonces] = env['rack.session']['omniauth.line.nonces']
        [200, {}, ['signed in']]
      }
    end.to_app
  end

  around do |example|
    saved = [OmniAuth.config.request_validation_phase, OmniAuth.config.on_failure, OmniAuth.config.logger]
    OmniAuth.config.request_validation_phase = nil
    OmniAuth.config.logger = Logger.new(IO::NULL)
    failures = seen
    OmniAuth.config.on_failure = lambda { |env|
      failures[:failure] = env['omniauth.error.type']
      failures[:nonces] = env['rack.session']['omniauth.line.nonces']
      [401, {}, ['refused']]
    }
    example.run
  ensure
    OmniAuth.config.request_validation_phase, OmniAuth.config.on_failure, OmniAuth.config.logger = saved
  end

  def start_sign_in
    post '/auth/line'
    uri = URI(last_response.headers['Location'])
    ["#{uri.scheme}://#{uri.host}#{uri.path}", Rack::Utils.parse_query(uri.query)]
  end

  def stub_token(body = {})
    stub_request(:post, 'https://api.line.me/oauth2/v2.1/token').to_return(
      status: 200, headers: { 'Content-Type' => 'application/json' },
      body: { access_token: 'access-token', token_type: 'Bearer', expires_in: 2_592_000,
              refresh_token: 'refresh-token', scope: 'profile openid', id_token: id_token }.merge(body).to_json
    )
  end

  def stub_profile
    stub_request(:get, 'https://api.line.me/v2/profile')
      .with(headers: { 'Authorization' => 'Bearer access-token' })
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' },
                 body: { userId: 'U4af4980629abc', displayName: 'Foo Bar',
                         pictureUrl: 'https://profile.line-scdn.net/abc.jpg' }.to_json)
  end

  def stub_verify(nonce:, status: 200, body: nil)
    claims = { iss: 'https://access.line.me', sub: 'U4af4980629abc', aud: 'channel-id',
               amr: ['linesso'], name: 'Foo Bar', email: 'foo@example.com', nonce: nonce }
    stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
      .with(body: { 'id_token' => id_token, 'client_id' => 'channel-id', 'nonce' => nonce })
      .to_return(status: status, body: (body || claims).to_json)
  end

  it 'sends the browser to LINE with a state, a nonce and a PKCE challenge' do
    endpoint, params = start_sign_in

    expect(endpoint).to eq('https://access.line.me/oauth2/v2.1/authorize')
    expect(params).to include('response_type' => 'code', 'client_id' => 'channel-id', 'scope' => 'profile openid',
                              'code_challenge_method' => 'S256')
    expect(params['redirect_uri']).to end_with('/auth/line/callback')
    expect(params.values_at('state', 'nonce', 'code_challenge')).to all(be_a(String).and(satisfy { |v| !v.empty? }))
  end

  it 'signs the user in, proving the code with the PKCE verifier and the ID token with the nonce' do
    _, params = start_sign_in
    token = stub_token
    stub_profile
    verify = stub_verify(nonce: params['nonce'])

    get '/auth/line/callback', code: 'one-time-code', state: params['state']

    expect(last_response.status).to eq(200)
    expect(token.with { |request|
      form = Rack::Utils.parse_query(request.body)
      challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(form['code_verifier'].to_s), padding: false)
      form.values_at('grant_type', 'code', 'client_id', 'client_secret') ==
        %w[authorization_code one-time-code channel-id channel-secret] &&
        form['redirect_uri'] == params['redirect_uri'] && challenge == params['code_challenge'] &&
        !request.headers.key?('Authorization')
    }).to have_been_requested.once
    expect(verify).to have_been_requested.once

    auth = seen[:auth]
    expect(auth.provider).to eq('line')
    expect(auth.uid).to eq('U4af4980629abc')
    expect(auth.info.to_h).to include('name' => 'Foo Bar', 'email' => 'foo@example.com',
                                      'image' => 'https://profile.line-scdn.net/abc.jpg')
    expect(auth.credentials.to_h).to include('token' => 'access-token', 'refresh_token' => 'refresh-token',
                                             'expires' => true)
    expect(auth.extra.id_token).to eq(id_token)
    expect(auth.extra.id_token_claims.to_h).to include('amr' => ['linesso'], 'sub' => 'U4af4980629abc')
  end

  it 'refuses the sign-in when LINE rejects the ID token for its nonce' do
    _, params = start_sign_in
    stub_token
    stub_profile
    stub_verify(nonce: params['nonce'], status: 400,
                body: { error: 'invalid_request', error_description: 'Invalid IdToken Nonce.' })

    get '/auth/line/callback', code: 'one-time-code', state: params['state']

    expect(last_response.status).to eq(401)
    expect(seen[:failure]).to eq(:invalid_credentials)
    expect(seen).not_to have_key(:auth)
  end

  it 'signs the user in without the ID token claims when the verify endpoint cannot be reached' do
    _, params = start_sign_in
    stub_token
    stub_profile
    stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify').to_raise(Errno::ECONNRESET)

    get '/auth/line/callback', code: 'one-time-code', state: params['state']

    expect(last_response.status).to eq(200)
    expect(seen[:auth].uid).to eq('U4af4980629abc')
    expect(seen[:auth].info['email']).to be_nil
    expect(seen[:auth].extra.to_h).not_to have_key('id_token_claims')
  end

  it 'reports a timeout when the profile API does not answer' do
    _, params = start_sign_in
    stub_token
    stub_request(:get, 'https://api.line.me/v2/profile').to_timeout
    stub_verify(nonce: params['nonce'])

    get '/auth/line/callback', code: 'one-time-code', state: params['state']

    expect(last_response.status).to eq(401)
    expect(seen[:failure]).to eq(:timeout)
  end

  it 'refuses a callback whose state the session did not issue' do
    start_sign_in
    token = stub_token

    get '/auth/line/callback', code: 'one-time-code', state: 'forged'

    expect(last_response.status).to eq(401)
    expect(seen[:failure]).to eq(:csrf_detected)
    expect(token).not_to have_been_requested
  end

  it 'refuses the sign-in when the ID token belongs to someone else' do
    _, params = start_sign_in
    stub_token
    stub_profile
    stub_verify(nonce: params['nonce'], body: { sub: 'Usomeoneelse', email: 'other@example.com' })

    get '/auth/line/callback', code: 'one-time-code', state: params['state']

    expect(last_response.status).to eq(401)
    expect(seen[:failure]).to eq(:invalid_credentials)
  end

  describe 'the stored nonce' do
    it 'is used once, and a sign-in started alongside keeps its own' do
      _, first = start_sign_in
      _, second = start_sign_in
      stub_token
      stub_profile
      first_verify = stub_verify(nonce: first['nonce'])

      get '/auth/line/callback', code: 'one-time-code', state: first['state']

      expect(first_verify).to have_been_requested.once
      expect(seen[:nonces]).to eq(second['state'] => second['nonce'])

      second_verify = stub_verify(nonce: second['nonce'])
      get '/auth/line/callback', code: 'another-code', state: second['state']

      expect(second_verify).to have_been_requested.once
      expect(seen[:nonces]).to eq({})
    end

    it 'is dropped when LINE sends the user back with an error' do
      _, params = start_sign_in

      get '/auth/line/callback', error: 'access_denied', state: params['state']

      expect(seen[:failure]).to eq(:access_denied)
      expect(seen[:nonces]).to eq({})
    end

    it 'is dropped when the token response carries no ID token' do
      _, params = start_sign_in
      stub_token(id_token: nil)
      stub_profile

      get '/auth/line/callback', code: 'one-time-code', state: params['state']

      expect(last_response.status).to eq(200)
      expect(seen[:nonces]).to eq({})
      expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')).not_to have_been_made
    end

    it 'is left alone by a callback with a forged state' do
      _, params = start_sign_in

      get '/auth/line/callback', code: 'one-time-code', state: 'forged'

      expect(seen[:nonces]).to eq(params['state'] => params['nonce'])
    end
  end

  it 'reports that the user added the official account when bot_prompt asked for it' do
    _, params = start_sign_in
    stub_token
    stub_profile
    stub_verify(nonce: params['nonce'])

    get '/auth/line/callback', code: 'one-time-code', state: params['state'], friendship_status_changed: 'true'

    expect(seen[:auth].extra.friendship_status_changed).to be(true)
  end

  context 'when the callback is handled without the session that started the sign-in' do
    let(:strategy_options) { { pkce: false, provider_ignores_state: true } }

    it 'signs the user in, verifying the ID token without a nonce' do
      stub_token
      stub_profile
      verify = stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
               .with(body: { 'id_token' => id_token, 'client_id' => 'channel-id' })
               .to_return(status: 200, body: { sub: 'U4af4980629abc', email: 'foo@example.com' }.to_json)

      get '/auth/line/callback', code: 'one-time-code', state: 'from-another-session'

      expect(last_response.status).to eq(200)
      expect(verify).to have_been_requested.once
      expect(seen[:auth].info['email']).to eq('foo@example.com')
      expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/token')
        .with { |request| !Rack::Utils.parse_query(request.body).key?('code_verifier') }).to have_been_made.once
    end
  end
end
