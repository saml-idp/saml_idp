# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "saml_idp/version"

Gem::Specification.new do |s|
  s.name = %q{saml_idp}
  s.version = SamlIdp::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ["Jon Phenow"]
  s.email = %q{jon.phenow@sportngin.com}
  s.homepage = %q{http://github.com/sportngin/saml_idp}
  s.summary = %q{SAML Indentity Provider in ruby}
  s.description = %q{SAML IdP (Identity Provider) library in ruby}
  s.date = Time.now.utc.strftime("%Y-%m-%d")
  s.files = Dir.glob("app/**/*") + Dir.glob("lib/**/*") + [
     "LICENSE",
     "README.md",
     "Gemfile",
     "saml_idp.gemspec"
  ]
  s.license = "LICENSE"
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.rdoc_options = ["--charset=UTF-8"]

  s.post_install_message = <<-INST
If you're just recently updating saml_idp - please be aware we've changed the default
certificate. See the PR and a description of why we've done this here:
https://github.com/sportngin/saml_idp/pull/29

If you just need to see the certificate `bundle open saml_idp` and go to
`lib/saml_idp/default.rb`

Similarly, please see the README about certificates - you should avoid using the
defaults in a Production environment. Post any issues you to github.
  INST

  s.add_dependency('activesupport')
  s.add_dependency('uuid')
  s.add_dependency('builder')
  s.add_dependency('httparty')
  s.add_dependency('nokogiri')

  s.add_development_dependency "rake"
  s.add_development_dependency "simplecov"
  s.add_development_dependency "rspec", "~> 2.5"
  s.add_development_dependency "ruby-saml", "~> 0.8.1"
  s.add_development_dependency("rails", "~> 3.2")
  s.add_development_dependency("capybara")
  s.add_development_dependency("timecop")
end

