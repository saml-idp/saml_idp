require 'saml_idp/logout_builder'
module SamlIdp
  class LogoutRequestBuilder < LogoutBuilder
    attr_accessor :name_id

    def initialize(
      response_id:,
      issuer_uri:,
      saml_slo_url:,
      name_id:,
      algorithm:,
      public_cert:,
      private_key:,
      pv_key_password: nil
    )
      super(
        response_id: response_id,
        issuer_uri: issuer_uri,
        saml_slo_url: saml_slo_url,
        algorithm: algorithm,
        public_cert: public_cert,
        private_key: private_key,
        pv_key_password: pv_key_password
      )
      self.name_id = name_id
    end

    def build
      builder = Builder::XmlMarkup.new
      builder.LogoutRequest ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: saml_slo_url,
        "xmlns" => SamlIdp::XML::Namespaces::PROTOCOL do |request|
          request.Issuer issuer_uri, xmlns: SamlIdp::XML::Namespaces::ASSERTION
          sign request
          request.NameID name_id, xmlns: SamlIdp::XML::Namespaces::ASSERTION,
            Format: SamlIdp::XML::Namespaces::Formats::NameId::PERSISTENT
          request.SessionIndex response_id_string
        end
    end
    private :build
  end
end
