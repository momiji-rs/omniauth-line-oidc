# Changelog

All notable changes to this gem are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release under the name `omniauth-line-oidc`. The gem continues the
`omniauth-line` strategy (last released as 0.1.0 in 2021) and keeps its
provider name, `:line`, so an app can switch by changing its Gemfile.

### Changed since `omniauth-line` 0.1.0

- Token exchange sends the channel secret in the request body, the only
  client authentication LINE documents.
- The authorization URL and the API calls use their own hosts
  (`access.line.me` and `api.line.me`) from fixed settings; nothing is
  rewritten per request.
- `info[:email]` is read from the ID token through LINE's verify endpoint.
  A failed or slow verify call yields `nil` for the email and does not fail
  the sign-in.
- The verify call has timeouts (5 s to open, 10 s to read), configurable
  through `verify_options`.
- LINE's authorization options are forwarded when set: `prompt`, `nonce`,
  `max_age`, `ui_locales`, `bot_prompt`, `initial_amr_display`, `switch_amr`,
  `disable_auto_login`, `disable_ios_auto_login`.
- The callback URL override is the `redirect_uri` option. `omniauth-line`
  0.1.0 read it from `callback_url`; rename the option when switching.
- A Faraday timeout while fetching the profile fails the sign-in as a
  timeout instead of raising; 0.1.0 caught only `Errno::ETIMEDOUT`.
- Requires Ruby 3.1 or newer, `omniauth` 2.x and `omniauth-oauth2` 1.8 or
  newer. The `json` gem is no longer a declared dependency.
