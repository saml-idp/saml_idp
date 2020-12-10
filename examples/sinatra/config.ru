# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'


if ENV['RACK_ENV'].nil? || ENV['RACK_ENV'] == 'development'
  require 'dotenv/load'
  require 'pry'
end

Bundler.require

require './app'

SamlIdp.configure do |config|
  config.x509_certificate = <<-CERT
-----BEGIN CERTIFICATE-----
CERT_CONTENT
-----END CERTIFICATE-----
  CERT

  config.secret_key = <<-CERT
-----BEGIN RSA PRIVATE KEY-----
KEY_CONTENT
-----END RSA PRIVATE KEY-----
CERT
  
  config.name_id.formats = {
    email_address: -> (principal) { principal.email_address },
    transient: -> (principal) { principal.id },
    persistent: -> (p) { p.id },
  }
end

run App
