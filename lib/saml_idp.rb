# encoding: utf-8
module SamlIdp
  require 'active_support/all'
  require 'saml_idp/saml_response'
  require 'saml_idp/xml_security'
  require 'saml_idp/configurator'
  require 'saml_idp/controller'
  require 'saml_idp/default'
  require 'saml_idp/metadata_builder'
  require 'saml_idp/version'
  require 'saml_idp/engine' if defined?(::Rails) && Rails::VERSION::MAJOR > 2

  def self.config
    @config ||= SamlIdp::Configurator.new
  end

  def self.configure
    yield config
  end

  def self.metadata
    @metadata ||= MetadataBuilder.new(config)
  end
end

# TODO Needs extraction out
module Saml
  module XML
    module Namespaces
      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      SIGNATURE = "http://www.w3.org/2000/09/xmldsig#"
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
    end

    class Document < Nokogiri::XML::Document
      def signed?
        !!xpath("//ds:Signature", ds: signature_namespace).first
      end

      def valid_signature?(fingerprint)
        signed? &&
          signed_document.validate(fingerprint, :soft)
      end

      def signed_document
        XMLSecurity::SignedDocument.new(to_xml)
      end

      def signature_namespace
        Namespaces::SIGNATURE
      end

      def to_xml
        super(
          save_with: Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
        ).strip
      end
    end
  end
end
