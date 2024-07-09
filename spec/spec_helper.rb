# encoding: utf-8
require 'simplecov'
SimpleCov.minimum_coverage 96.45
SimpleCov.start do
  add_filter "/spec/"
end
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'
$LOAD_PATH.unshift File.dirname(__FILE__)

STDERR.puts("Running Specs under Ruby Version #{RUBY_VERSION}")

require "rails_app/config/environment"

require 'rspec'
require 'capybara/rspec'
require 'capybara/rails'

require 'ruby-saml'
require 'saml_idp'
require 'timecop'

Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each {|f| require f}

RSpec.configure do |config|
  config.mock_with :rspec
  config.order = "random"

  config.include SamlRequestMacros
  config.include SecurityHelpers

  config.before do
    SamlIdp.configure do |c|
      c.attributes = {
        emailAddress: {
          name: "email-address",
          getter: ->(p) { "foo@example.com" }
        }
      }

      c.name_id.formats = {
        "1.1" => {
          email_address: ->(p) { "foo@example.com" }
        }
      }
    end
  end

  # To reset to default config
  config.after do
    SamlIdp.instance_variable_set(:@config, nil)
    SamlIdp.configure do |c|
      c.attributes = {
        emailAddress: {
          name: "email-address",
          getter: ->(p) { "foo@example.com" }
        }
      }

      c.name_id.formats = {
        "1.1" => {
          email_address: ->(p) { "foo@example.com" }
        }
      }
    end
  end
end

SamlIdp::Default::SERVICE_PROVIDER[:metadata_url] = 'https://example.com/meta'
SamlIdp::Default::SERVICE_PROVIDER[:response_hosts] = ['foo.example.com']
SamlIdp::Default::SERVICE_PROVIDER[:assertion_consumer_logout_service_url] = 'https://foo.example.com/saml/logout'
Capybara.default_host = "https://foo.example.com"
