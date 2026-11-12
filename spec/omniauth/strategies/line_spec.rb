require 'spec_helper'

describe OmniAuth::Strategies::Line do
  let(:request) { double('Request', :params => {}, :cookies => {}, :env => {}) }
  let(:app) { lambda { |_env| [200, {}, ['']] } }

  subject do
    args = ['channel_id', 'secret', @options || {}].compact
    OmniAuth::Strategies::Line.new(app, *args).tap do |strategy|
      allow(strategy).to receive(:request) {
        request
      }
    end
  end

  describe 'client options' do
    it 'should have correct name' do
      expect(subject.options.name).to eq('line')
    end

    it 'should have correct site' do
      expect(subject.options.client_options.site).to eq('https://api.line.me')
    end

    it 'should have correct authorize url' do
      expect(subject.options.client_options.authorize_url).to eq('https://access.line.me/oauth2/v2.1/authorize')
    end

    it 'should have correct token url' do
      expect(subject.options.client_options.token_url).to eq('/oauth2/v2.1/token')
    end

    it 'should build the authorize url on access.line.me' do
      expect(subject.client.authorize_url).to start_with('https://access.line.me/oauth2/v2.1/authorize')
    end

    it 'should build the token url on api.line.me' do
      expect(subject.client.token_url).to eq('https://api.line.me/oauth2/v2.1/token')
    end

    it 'should send client credentials in the token request body' do
      stub_request(:post, 'https://api.line.me/oauth2/v2.1/token')
        .to_return(:status => 200, :body => { 'access_token' => 't' }.to_json,
                   :headers => { 'Content-Type' => 'application/json' })
      subject.client.auth_code.get_token('a-code', redirect_uri: 'https://example.com/cb')
      expect(
        a_request(:post, 'https://api.line.me/oauth2/v2.1/token')
          .with(:body => hash_including('client_id' => 'channel_id', 'client_secret' => 'secret'))
      ).to have_been_made
    end
  end

  describe 'authorize params' do
    it 'should forward LINE-specific options to the authorize request' do
      @options = { prompt: 'consent', bot_prompt: 'normal', ui_locales: 'zh-TW', redirect_uri: 'https://app.test/auth/line/callback' }
      allow(subject).to receive(:session).and_return({})
      params = subject.authorize_params
      expect(params[:prompt]).to eq('consent')
      expect(params[:bot_prompt]).to eq('normal')
      expect(params[:ui_locales]).to eq('zh-TW')
    end

    it 'should not forward options outside the whitelist' do
      @options = { channel_secret: 'super-secret', redirect_uri: 'https://app.test/auth/line/callback' }
      allow(subject).to receive(:session).and_return({})
      expect(subject.authorize_params).not_to have_key(:channel_secret)
    end

    context 'with a session' do
      let(:session) { {} }
      let(:redirect_uri) { 'https://app.test/auth/line/callback' }

      # The strategy reads @options when it is built, so the options go in
      # before the first use of subject.
      def strategy_with(options)
        @options = { redirect_uri: redirect_uri }.merge(options)
        allow(subject).to receive(:session).and_return(session)
        subject
      end

      it 'should generate a nonce and store it under the state' do
        params = strategy_with({}).authorize_params

        expect(params[:nonce]).to match(/\A[0-9a-f]{32}\z/)
        expect(session['omniauth.line.nonces']).to eq(params[:state] => params[:nonce])
      end

      it 'should keep a nonce the application set' do
        params = strategy_with(nonce: 'app-chosen-nonce').authorize_params

        expect(params[:nonce]).to eq('app-chosen-nonce')
        expect(session['omniauth.line.nonces']).to eq(params[:state] => 'app-chosen-nonce')
      end

      it 'should send no nonce when the scope asks for no ID token' do
        expect(strategy_with(scope: 'profile').authorize_params).not_to have_key(:nonce)
        expect(session).not_to have_key('omniauth.line.nonces')
      end

      it 'should keep a nonce for each sign-in a session has under way, dropping the oldest' do
        strategy = strategy_with({})
        states = Array.new(6) { strategy.authorize_params[:state] }

        expect(session['omniauth.line.nonces'].keys).to eq(states.last(5))
      end

      it 'should send a PKCE challenge by default' do
        params = strategy_with({}).authorize_params

        expect(params[:code_challenge_method]).to eq('S256')
        expect(params[:code_challenge]).to match(/\A[A-Za-z0-9_-]{43}\z/)
      end

      it 'should send no PKCE challenge when it is turned off' do
        expect(strategy_with(pkce: false).authorize_params).not_to have_key(:code_challenge)
      end
    end
  end

  describe 'callback_url' do
    it 'should exclude the query string' do
      allow(subject).to receive(:full_host).and_return('https://example.com')
      allow(subject).to receive(:script_name).and_return('')
      expect(subject.callback_url).to eq('https://example.com/auth/line/callback')
    end

    it 'should prefer an explicitly configured redirect_uri' do
      @options = { redirect_uri: 'https://school.example.com/api/auth/line/callback' }
      expect(subject.callback_url).to eq('https://school.example.com/api/auth/line/callback')
    end

    it 'should accept callback_url, the option name omniauth-line used' do
      @options = { callback_url: 'https://legacy.example.com/auth/line/callback' }
      expect(subject.callback_url).to eq('https://legacy.example.com/auth/line/callback')
    end

    it 'should prefer redirect_uri when both are set' do
      @options = { redirect_uri: 'https://new.example.com/cb', callback_url: 'https://legacy.example.com/cb' }
      expect(subject.callback_url).to eq('https://new.example.com/cb')
    end
  end

  describe 'callback data' do
    let(:id_token) { 'header.payload.signature' }
    let(:access_token) do
      OAuth2::AccessToken.new(subject.client, 'access-token',
                              'id_token' => id_token, 'scope' => 'profile openid')
    end

    let(:profile_response) do
      {
        'userId'        => 'U4af4980629abc',
        'displayName'   => 'Foo Bar',
        'pictureUrl'    => 'https://profile.line-scdn.net/abc.jpg',
        'statusMessage' => 'Developer'
      }
    end

    let(:verify_response) do
      {
        'iss'   => 'https://access.line.me',
        'sub'   => 'U4af4980629abc',
        'email' => 'foo@example.com'
      }
    end

    let(:session) { {} }

    before do
      allow(subject).to receive(:access_token).and_return(access_token)
      allow(subject).to receive(:session).and_return(session)

      stub_request(:get, 'https://api.line.me/v2/profile')
        .with(:headers => { 'Authorization' => 'Bearer access-token' })
        .to_return(:status => 200, :body => profile_response.to_json,
                   :headers => { 'Content-Type' => 'application/json' })

      stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
        .with(:body => { 'id_token' => id_token, 'client_id' => 'channel_id' })
        .to_return(:status => 200, :body => verify_response.to_json,
                   :headers => { 'Content-Type' => 'application/json' })
    end

    describe 'uid' do
      it 'should return the userId from the profile' do
        expect(subject.uid).to eq('U4af4980629abc')
      end
    end

    describe 'info' do
      it 'should return the name' do
        expect(subject.info[:name]).to eq('Foo Bar')
      end

      it 'should return the image' do
        expect(subject.info[:image]).to eq('https://profile.line-scdn.net/abc.jpg')
      end

      it 'should return the description' do
        expect(subject.info[:description]).to eq('Developer')
      end

      it 'should return the email decoded from the id token' do
        expect(subject.info[:email]).to eq('foo@example.com')
      end
    end

    describe 'extra' do
      it 'should contain the id token' do
        expect(subject.extra[:id_token]).to eq(id_token)
      end

      it 'should contain the verified id token claims' do
        expect(subject.extra[:id_token_claims]).to eq(verify_response)
      end

      it 'should contain the profile' do
        expect(subject.extra[:raw_info]).to eq(profile_response)
      end

      it 'should verify the id token once however many claims are read' do
        subject.info
        subject.extra
        subject.uid
        expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')).to have_been_made.once
      end

      it 'should leave out claims the verify endpoint rejected' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 400, :body => { 'error' => 'invalid_request' }.to_json)
        expect(subject.extra).to eq(raw_info: profile_response, id_token: id_token)
      end
    end

    describe 'friendship status' do
      it 'should be absent when LINE did not report it' do
        expect(subject.extra).not_to have_key(:friendship_status_changed)
      end

      it 'should be true when the user added the official account during sign-in' do
        allow(request).to receive(:params).and_return('friendship_status_changed' => 'true')
        expect(subject.extra[:friendship_status_changed]).to be(true)
      end

      it 'should be false when the friendship did not change' do
        allow(request).to receive(:params).and_return('friendship_status_changed' => 'false')
        expect(subject.extra[:friendship_status_changed]).to be(false)
      end
    end

    describe 'nonce verification' do
      let(:request) { double('Request', :params => { 'state' => 'state-1' }, :cookies => {}, :env => {}) }

      it 'should send the nonce stored for this state to the verify endpoint' do
        session['omniauth.line.nonces'] = { 'state-0' => 'nonce-0', 'state-1' => 'nonce-1' }
        verify = stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
                 .with(:body => { 'id_token' => id_token, 'client_id' => 'channel_id', 'nonce' => 'nonce-1' })
                 .to_return(:status => 200, :body => verify_response.to_json)

        expect(subject.email).to eq('foo@example.com')
        expect(verify).to have_been_requested.once
      end

      it 'should use a nonce once and leave other sign-ins theirs' do
        session['omniauth.line.nonces'] = { 'state-0' => 'nonce-0', 'state-1' => 'nonce-1' }
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 200, :body => verify_response.to_json)

        subject.email

        expect(session['omniauth.line.nonces']).to eq('state-0' => 'nonce-0')
      end

      it 'should verify without a nonce when the session started no sign-in for this state' do
        session['omniauth.line.nonces'] = { 'state-0' => 'nonce-0' }

        expect(subject.email).to eq('foo@example.com')
        expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .with(:body => { 'id_token' => id_token, 'client_id' => 'channel_id' })).to have_been_made.once
        expect(session['omniauth.line.nonces']).to eq('state-0' => 'nonce-0')
      end

      it 'should use no claim from a token LINE rejects for its nonce' do
        session['omniauth.line.nonces'] = { 'state-1' => 'nonce-1' }
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 400,
                     :body => { 'error' => 'invalid_request', 'error_description' => 'Invalid IdToken Nonce.' }.to_json)

        expect(subject.info[:email]).to be_nil
        expect(subject.extra).not_to have_key(:id_token_claims)
        expect(subject.uid).to eq('U4af4980629abc')
      end
    end

    describe 'the id token subject' do
      it 'should fail the sign-in when it names a different user than the profile' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 200, :body => verify_response.merge('sub' => 'Usomeoneelse').to_json)

        expect { subject.uid }.to raise_error(OmniAuth::Strategies::OAuth2::CallbackError, /different users/)
      end
    end

    describe 'raw_info' do
      it 'should memoize the profile request' do
        2.times { subject.raw_info }
        expect(a_request(:get, 'https://api.line.me/v2/profile')).to have_been_made.once
      end

      it 'should convert profile connection timeouts into Timeout::Error' do
        stub_request(:get, 'https://api.line.me/v2/profile').to_raise(Errno::ETIMEDOUT)
        expect { subject.raw_info }.to raise_error(Timeout::Error)
      end
    end

    describe 'email degradation' do
      it 'should return no email when the verify call times out' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify').to_timeout
        expect(subject.info[:email]).to be_nil
      end

      it 'should return no email when the verify call is rejected' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 400,
                     :body => { 'error' => 'invalid_request', 'error_description' => 'Invalid IdToken.' }.to_json,
                     :headers => { 'Content-Type' => 'application/json' })
        expect(subject.info[:email]).to be_nil
      end

      it 'should return no email when the verify response is not JSON' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 502, :body => '<html>Bad Gateway</html>')
        expect(subject.info[:email]).to be_nil
      end

      it 'should fall back to default timeouts when verify_options is overridden away' do
        @options = { verify_options: nil }
        expect(subject.info[:email]).to eq('foo@example.com')
      end

      it 'should log a warning on verify failure' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 400,
                     :body => { 'error' => 'invalid_request', 'error_description' => 'Invalid IdToken.' }.to_json,
                     :headers => { 'Content-Type' => 'application/json' })
        expect(subject).to receive(:log).with(:warn, /Invalid IdToken/)
        subject.info
      end
    end

    context 'when no id token was issued' do
      let(:access_token) do
        OAuth2::AccessToken.new(subject.client, 'access-token', 'scope' => 'profile')
      end

      it 'should return no email' do
        expect(subject.info[:email]).to be_nil
      end

      it 'should not call the verify endpoint' do
        subject.info
        expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')).not_to have_been_made
      end

      it 'should carry only the profile in extra' do
        expect(subject.extra).to eq(raw_info: profile_response)
      end
    end

    context 'when the user did not grant the email permission' do
      before do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
          .to_return(:status => 200,
                     :body => { 'iss' => 'https://access.line.me', 'sub' => 'U1234567890' }.to_json,
                     :headers => { 'Content-Type' => 'application/json' })
      end

      it 'should return no email' do
        expect(subject.info[:email]).to be_nil
      end
    end
  end

  # Cassettes under spec/cassettes were recorded against the real LINE API
  # with throwaway credentials (no secrets involved); CI only replays them.
  describe 'recorded LINE API behavior' do
    let(:access_token) do
      OAuth2::AccessToken.new(subject.client, 'invalid-access-token',
                              'id_token' => 'bogus.id.token', 'scope' => 'profile openid')
    end

    before do
      allow(subject).to receive(:access_token).and_return(access_token)
      allow(subject).to receive(:session).and_return({})
    end

    it 'should degrade to a nil email when LINE rejects the id token' do
      VCR.use_cassette('verify_invalid_id_token') do
        expect(subject.email).to be_nil
      end
    end

    it 'should raise OAuth2::Error when LINE rejects the profile access token' do
      VCR.use_cassette('profile_invalid_access_token') do
        expect { subject.raw_info }.to raise_error(OAuth2::Error)
      end
    end

    it 'should raise OAuth2::Error when the token exchange is rejected' do
      VCR.use_cassette('token_invalid_client') do
        expect {
          subject.client.auth_code.get_token('bogus-code',
                                             redirect_uri: 'https://example.com/auth/line/callback')
        }.to raise_error(OAuth2::Error)
      end
    end
  end
end
