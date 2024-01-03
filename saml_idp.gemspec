# -*- encoding: utf-8 -*-

$LOAD_PATH.push File.expand_path('lib', __dir__)
require 'saml_idp/version'

Gem::Specification.new do |s|
  s.name = %q{saml_idp}
  s.version = SamlIdp::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ['Jon Phenow']
  s.email = 'jon.phenow@sportngin.com'
  s.homepage = 'https://github.com/saml-idp/saml_idp'
  s.summary = 'SAML Indentity Provider for Ruby'
  s.description = 'SAML IdP (Identity Provider) Library for Ruby'
  s.date = Time.now.utc.strftime('%Y-%m-%d')
  s.files = Dir['lib/**/*', 'LICENSE', 'README.md', 'Gemfile', 'saml_idp.gemspec']
  s.required_ruby_version = '>= 2.5'
  s.license = 'MIT'
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ['lib']
  s.rdoc_options = ['--charset=UTF-8']
  s.metadata = {
    'homepage_uri' => 'https://github.com/saml-idp/saml_idp',
    'source_code_uri' => 'https://github.com/saml-idp/saml_idp',
    'bug_tracker_uri' => 'https://github.com/saml-idp/saml_idp/issues',
    'documentation_uri' => "http://rdoc.info/gems/saml_idp/#{SamlIdp::VERSION}"
  }

  s.post_install_message = <<-INST
    If you're just recently updating saml_idp - please be aware we've changed the default
    certificate. See the PR and a description of why we've done this here:
    https://github.com/saml-idp/saml_idp/pull/29

    If you just need to see the certificate `bundle open saml_idp` and go to
    `lib/saml_idp/default.rb`

    Similarly, please see the README about certificates - you should avoid using the
    defaults in a Production environment. Post any issues you to github.

    ** New in Version 0.3.0 **
    Encrypted Assertions require the xmlenc gem. See the example in the Controller
    section of the README.
  INST

  s.add_dependency('activesupport', '>= 5.2')
  s.add_dependency('builder', '>= 3.0')
  s.add_dependency('nokogiri', '>= 1.6.2')
  s.add_dependency('rexml')
  s.add_dependency('xmlenc', '>= 0.7.1')

  s.add_development_dependency('activeresource', '>= 5.1')
  s.add_development_dependency('appraisal')
  s.add_development_dependency('byebug')
  s.add_development_dependency('capybara', '>= 2.16')
  s.add_development_dependency('rails', '>= 5.2')
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec', '>= 3.7.0')
  s.add_development_dependency('ruby-saml', '>= 1.7.2')
  s.add_development_dependency('simplecov')
  s.add_development_dependency('timecop', '>= 0.8')
end
