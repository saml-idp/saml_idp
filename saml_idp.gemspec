# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "saml_idp/version"

Gem::Specification.new do |s|
  s.name = %q{saml_idp}
  s.version = SamlIdp::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ["Bravo Wellness, LLC"]
  s.email = 'info@bravowell.com'
  s.homepage = 'https://bitbucket.org/bravowellnesss/saml_idp'
  s.summary = 'SAML Indentity Provider for Ruby'
  s.description = 'SAML IdP (Identity Provider) Library for Ruby'
  s.date = Time.now.utc.strftime("%Y-%m-%d")
  s.files = Dir['lib/**/*', 'LICENSE', 'README.md', 'Gemfile', 'saml_idp.gemspec']
  s.required_ruby_version = '>= 2.5'
  s.license = 'MIT'
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.rdoc_options = ['--charset=UTF-8']
  s.metadata = {
    'homepage_uri'      => 'https://bitbucket.org/bravowellnesss/saml_idp',
    'source_code_uri'   => 'https://bitbucket.org/bravowellnesss/saml_idp',
    'bug_tracker_uri'   => 'https://bitbucket.org/bravowellnesss/saml_idp/issues',
    'documentation_uri' => "http://rdoc.info/gems/saml_idp/#{SamlIdp::VERSION}"
  }

  s.add_dependency('activesupport', '>= 3.2')
  s.add_dependency('uuid', '>= 2.3')
  s.add_dependency('builder', '>= 3.0')
  s.add_dependency('nokogiri', '>= 1.6.2')
  s.add_dependency('xmlenc', '>= 0.7.1')
  s.add_dependency('rexml')

  s.add_development_dependency('rake')
  s.add_development_dependency('simplecov')
  s.add_development_dependency('rspec', '>= 3.7.0')
  s.add_development_dependency('ruby-saml', '>= 1.7.2')
  s.add_development_dependency('rails', '>= 5.2')
  s.add_development_dependency('activeresource', '>= 5.1')
  s.add_development_dependency('capybara', '>= 2.16')
  s.add_development_dependency('timecop', '>= 0.8')
  s.add_development_dependency('appraisal')
  s.add_development_dependency('byebug')
end
