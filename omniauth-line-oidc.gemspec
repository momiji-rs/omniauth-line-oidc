# frozen_string_literal: true

require_relative 'lib/omniauth/line_oidc/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-line-oidc'
  spec.version = OmniAuth::LineOidc::VERSION
  spec.authors = ['kazasiki', 'omniauth-line-oidc contributors']
  spec.summary = 'OmniAuth strategy for LINE Login v2.1 (OpenID Connect)'
  spec.description = 'Sign in with LINE through OmniAuth: LINE Login v2.1 with OpenID Connect, ' \
                     'including the email claim and LINE-specific authorization options.'
  spec.homepage = 'https://github.com/momiji-rs/omniauth-line-oidc'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.metadata = {
    'source_code_uri' => "#{spec.homepage}/tree/master",
    'changelog_uri' => "#{spec.homepage}/blob/master/CHANGELOG.md",
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'rubygems_mfa_required' => 'true'
  }

  spec.files = Dir['lib/**/*.rb', 'CHANGELOG.md', 'LICENSE.txt', 'README.md']
  spec.require_paths = ['lib']

  # omniauth-oauth2 1.10 is the first release that keeps state and the PKCE
  # verifier per sign-in, so that two started in one session both complete.
  spec.add_dependency 'omniauth', '~> 2.3', '>= 2.3.1'
  spec.add_dependency 'omniauth-oauth2', '~> 1.10'
end
