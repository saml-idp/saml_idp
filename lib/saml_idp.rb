# encoding: utf-8
module SamlIdp
  require 'active_support/all'
  require 'saml_idp/saml_response'
  require 'saml_idp/xml_security'
  require 'saml_idp/idp_config'
  require 'saml_idp/controller'
  require 'saml_idp/default'
  require 'saml_idp/metadata_builder'
  require 'saml_idp/version'
  require 'saml_idp/fingerprint'
  require 'saml_idp/engine' if defined?(::Rails)

  def self.saml_idp_global_config
    @saml_idp_global_config ||= OpenStruct.new(logger: ::Logger.new($stdout))
  end

  def self.config
    yield saml_idp_global_config
  end
end
