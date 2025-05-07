require 'saml_idp/attributeable'
module SamlIdp
  class PersistedMetadata
    include Attributeable
    attribute :signing_certificate
    attribute :encryption_certificate
    attribute :unspecified_certificate

    def sign_assertions?
      !!attributes[:sign_assertions]
    end

    def sign_authn_request?
      !!attributes[:sign_authn_request]
    end
  end
end
