require 'saml_idp/logout_builder'
module SamlIdp
  class LogoutResponseBuilder < LogoutBuilder
    attr_accessor :idp_config, :saml_request

    def initialize(idp_config:, saml_request:, response_id: nil)
      @response_id = response_id || SecureRandom.uuid
      self.saml_request = saml_request
      self.idp_config = idp_config
      super(@response_id, idp_config.issuer_uri, idp_config.single_logout_url, idp_config.algorithm)
    end
    
    def build
      builder = Builder::XmlMarkup.new
      builder.LogoutResponse ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: idp_config.single_logout_url,
        InResponseTo: saml_request.request_id,
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
