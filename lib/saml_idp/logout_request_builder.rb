require 'saml_idp/logout_builder'
module SamlIdp
  class LogoutRequestBuilder < LogoutBuilder
    attr_accessor :name_id

    def initialize(
      response_id,
      issuer_uri,
      saml_slo_url,
      name_id,
      algorithm,
      x509_certificate = nil,
      secret_key = nil,
      password = nil
    )
      super(response_id, issuer_uri, saml_slo_url, algorithm, x509_certificate, secret_key, password)
      self.name_id = name_id
    end

    def build
      builder = Builder::XmlMarkup.new
      builder.LogoutRequest ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: saml_slo_url,
        "xmlns" => Saml::XML::Namespaces::PROTOCOL do |request|
          request.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          sign request
          request.NameID name_id, xmlns: Saml::XML::Namespaces::ASSERTION,
            Format: Saml::XML::Namespaces::Formats::NameId::PERSISTENT
          request.SessionIndex response_id_string
        end
    end
    private :build
  end
end
