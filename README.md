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
(`/auth/line/callback`) and the auth hash keys are the same. Two things to
check:

- If you set the callback URL explicitly, the option is now `redirect_uri`
  (`omniauth-line` read `callback_url`).
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
profile API; the strategy decodes it via LINE's verify endpoint. When
the `email` scope is not granted, `info[:email]` is `nil`.

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
    id_token: "eyJ0eXAiOiJKV1Qi..."  # OpenID Connect ID token (JWT), issued with the openid scope
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
