# Changelog

All notable changes to this gem are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-12

First release under the name `omniauth-line-oidc`. The gem continues the
`omniauth-line` strategy (last released as 0.1.0 in 2021) and keeps its
provider name, `:line`, so an app can switch by changing its Gemfile.

### Added

- A `nonce` is generated for every authorization request that asks for an
  ID token, kept in the session under the request's `state`, and sent to
  LINE's verify endpoint with the ID token on the callback.
- The sign-in fails with `invalid_credentials` when LINE rejects the ID
  token, for its nonce or anything else.
- PKCE (`S256`) is on by default. Turn it off with `pkce: false`.
- `extra[:id_token_claims]`: the ID token's claims as LINE's verify
  endpoint returned them, including `amr`. Present only for a verified
  token.
- `extra[:raw_info]`: the profile API response.
- `extra[:friendship_status_changed]`, when LINE reports it on the callback
  (`bot_prompt`).
- The sign-in fails with `invalid_credentials` when the verified ID token
  names a different user than the profile.

### Changed since `omniauth-line` 0.1.0

- Token exchange sends the channel secret in the request body, one of the
  two client authentication methods LINE documents.
- The authorization URL and the API calls use their own hosts
  (`access.line.me` and `api.line.me`) from fixed settings; nothing is
  rewritten per request.
- `info[:email]` is read from the ID token through LINE's verify endpoint.
  When the endpoint cannot be reached, times out or answers with a server
  error, the email is `nil` and the sign-in carries on.
- The verify call has timeouts (5 s to open, 10 s to read), configurable
  through `verify_options`.
- LINE's authorization options are forwarded when set: `prompt`, `max_age`,
  `ui_locales`, `bot_prompt`, `initial_amr_display`, `switch_amr`,
  `disable_auto_login`, `disable_ios_auto_login`. A `nonce` option is
  ignored; the strategy generates one per sign-in.
- The callback URL override is the `redirect_uri` option. `callback_url`,
  the name `omniauth-line` 0.1.0 used, is still accepted.
- A profile response that is not JSON, or names no user, fails the sign-in
  with `invalid_credentials`.
- Requires Ruby 3.1 or newer, `omniauth` 2.3.1 or newer and
  `omniauth-oauth2` 1.10 or newer. The `json` gem is no longer a declared
  dependency.
