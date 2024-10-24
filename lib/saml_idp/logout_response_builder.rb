require 'saml_idp/logout_builder'
module SamlIdp
  class LogoutResponseBuilder < LogoutBuilder
    attr_accessor :saml_request_id

    def initialize(
      response_id,
      issuer_uri,
      saml_slo_url,
      saml_request_id,
      algorithm,
      x509_certificate = nil,
      secret_key = nil,
      password = nil
    )
      super(response_id, issuer_uri, saml_slo_url, algorithm, x509_certificate, secret_key, password)
      self.saml_request_id = saml_request_id
    end

    def build
      builder = Builder::XmlMarkup.new
      builder.LogoutResponse ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: saml_slo_url,
        InResponseTo: saml_request_id,
        xmlns: Saml::XML::Namespaces::PROTOCOL do |response|
          response.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          sign response
          response.Status xmlns: Saml::XML::Namespaces::PROTOCOL do |status|
            status.StatusCode Value: Saml::XML::Namespaces::Statuses::SUCCESS
          end
        end
    end
    private :build
  end
end
