# omniauth-line-oidc

[![CI](https://github.com/momiji-rs/omniauth-line-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/momiji-rs/omniauth-line-oidc/actions/workflows/ci.yml)

LINE Login v2.1 (OAuth 2.0 / OpenID Connect) strategy for OmniAuth.

See the LINE Login docs for details:
https://developers.line.biz/en/docs/line-login/integrate-line-login/

This gem continues the `omniauth-line` strategy, which has had no release
since 2021. It registers the same provider name, `:line`.

## Using This Strategy

First start by adding this gem to your Gemfile:

```ruby
gem 'omniauth-line-oidc'
```

### Switching from `omniauth-line`

Replace the gem in your Gemfile; the provider name, the callback path
(`/auth/line/callback`) and the auth hash keys are the same. Three things
to check:

- PKCE is on by default. It needs nothing from you unless your callback is
  handled without the session that started the sign-in; see
  [Callbacks handled by another session](#callbacks-handled-by-another-session).
- `extra` now also carries `raw_info`, and `id_token_claims` when the ID
  token was verified.
- Do not keep both gems in one bundle: both define
  `OmniAuth::Strategies::Line`.

See the [changelog](CHANGELOG.md) for everything that differs from
`omniauth-line` 0.1.0.

Next, tell OmniAuth about this provider. For a Rails app, your
`config/initializers/omniauth.rb` file should look like this:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :line, ENV['LINE_CHANNEL_ID'], ENV['LINE_CHANNEL_SECRET']
end
```

Register your callback URL (e.g. `https://your.app/auth/line/callback`)
under "LINE Login > Callback URL" in the
[LINE Developers console](https://developers.line.biz/console/), or the
authorization request will fail with "Invalid redirect_uri value".

### Scopes and email

The default scope is `profile openid`. To receive the user's email
address, apply for the "OpenID Connect email" permission in the LINE
Developers console and request the `email` scope:

```ruby
provider :line, ENV['LINE_CHANNEL_ID'], ENV['LINE_CHANNEL_SECRET'],
         scope: 'profile openid email'
```

LINE only exposes the email inside the ID token, never through the
profile API. When the `email` scope is not granted, `info[:email]` is
`nil`.

### Options

Besides the standard OmniAuth options, the strategy forwards these to
LINE's authorization URL when you set them: `prompt`, `max_age`,
`ui_locales`, `bot_prompt`, `initial_amr_display`, `switch_amr`,
`disable_auto_login`, `disable_ios_auto_login`, `nonce`.

```ruby
provider :line, ENV['LINE_CHANNEL_ID'], ENV['LINE_CHANNEL_SECRET'],
         bot_prompt: 'normal', ui_locales: 'ja'
```

| Option | Default | Meaning |
|---|---|---|
| `scope` | `'profile openid'` | Add `email` once the channel has the permission |
| `pkce` | `true` | Send a PKCE challenge (`S256`, the only method LINE accepts) |
| `redirect_uri` | built from the request | The callback URL registered with LINE. `callback_url`, the name `omniauth-line` used, is accepted too |
| `verify_options` | `{ open_timeout: 5, read_timeout: 10 }` | Timeouts for the ID token verify call, in seconds |

`response_mode` is not supported: the strategy reads the callback from
the query string, which is LINE's default.

## How the ID token is used

The user is identified by LINE's profile API, called with the access
token the sign-in was just issued. The ID token adds what the profile
API does not have, the email above all.

- The strategy sends a `nonce` with every authorization request that
  asks for an ID token, and keeps it in the session under the request's
  `state`.
- On the callback it sends the ID token, the channel ID and that nonce
  to LINE's [verify endpoint](https://developers.line.biz/en/reference/line-login/#verify-id-token).
  LINE checks the signature, issuer, audience, expiry and nonce.
- Claims are used only from a token LINE accepted. If the verify call is
  rejected or times out, the sign-in continues without them:
  `info[:email]` is `nil` and `extra[:id_token_claims]` is absent. A
  warning is logged.
- If the verified token names a different user than the profile, the
  sign-in fails with `invalid_credentials`.

The raw `extra[:id_token]` is passed through as LINE issued it. Do not
read claims out of it yourself; use `extra[:id_token_claims]`, which is
only present after verification.

### Callbacks handled by another session

The nonce and the PKCE verifier live in the session that started the
sign-in. If your callback arrives in a different session (for example a
front end on another domain relays it to your API), the strategy cannot
find them:

- Set `pkce: false`, or the token exchange is sent without a verifier
  and LINE rejects it.
- The ID token is then verified without a nonce. Everything else about
  it is still checked.
- You will also need `provider_ignores_state: true`, which gives up the
  CSRF protection `state` provides. Prefer carrying the session across
  if you can.

## Authentication Hash

An example auth hash available in `request.env['omniauth.auth']`:

```ruby
{
  provider: "line",
  uid: "U1234567890abcdef1234567890abcdef",
  info: {
    name: "yamada tarou",
    image: "https://profile.line-scdn.net/xxxxx",
    description: nil,            # the user's status message, may be nil
    email: "user@example.com"    # nil unless the email scope is granted
  },
  credentials: {
    token: "a1b2c3d4...",        # OAuth 2.0 access token
    refresh_token: "e5f6g7h8...",
    expires_at: 1789266388,
    expires: true
  },
  extra: {
    raw_info: {                  # the profile API response
      "userId" => "U1234567890abcdef1234567890abcdef",
      "displayName" => "yamada tarou",
      "pictureUrl" => "https://profile.line-scdn.net/xxxxx"
    },
    id_token: "eyJ0eXAiOiJKV1Qi...",  # as issued; present with the openid scope
    id_token_claims: {           # present only when LINE verified the token
      "iss" => "https://access.line.me",
      "sub" => "U1234567890abcdef1234567890abcdef",
      "aud" => "1234567890",
      "exp" => 1789266388,
      "iat" => 1789262788,
      "nonce" => "0f3c...",
      "amr" => ["linesso"],      # how the user authenticated
      "name" => "yamada tarou",
      "email" => "user@example.com"
    },
    friendship_status_changed: true   # present only when bot_prompt was requested
  }
}
```

## Development

```sh
bundle install
bundle exec rake   # runs the specs with a minimum-coverage gate
```

The test suite stubs all HTTP with WebMock; no LINE credentials are
needed. CI runs the suite on Ruby 3.1 through 3.4.
