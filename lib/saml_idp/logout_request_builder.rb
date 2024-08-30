require 'saml_idp/logout_builder'
module SamlIdp
  class LogoutRequestBuilder < LogoutBuilder
    include SamlIdp::Signable

    attr_accessor :name_id
    attr_accessor :reference_id

    def initialize(response_id, issuer_uri, saml_slo_url, name_id, algorithm)
      super(response_id, issuer_uri, saml_slo_url, algorithm)
      self.name_id = name_id
    end

    def build
      req_options = {}
      req_options[:ID] = "_#{reference_id}"
      req_options[:Version] = "2.0"
      req_options[:IssueInstant] = now_iso
      req_options[:Destination] = saml_slo_url
      req_options["xmlns:samlp"] = Saml::XML::Namespaces::PROTOCOL
      req_options["xmlns:saml"] = Saml::XML::Namespaces::ASSERTION
      req_options[:NotOnOrAfter] = (Time.now + 180).utc.iso8601
      builder = Builder::XmlMarkup.new
      builder.tag! "samlp:LogoutRequest", req_options do |request|
        request.tag! "saml:Issuer", issuer_uri
        sign request
        request.tag! "saml:NameID", name_id, Format: Saml::XML::Namespaces::Formats::NameId::PERSISTENT
      end
    end
    private :build
  end
end
