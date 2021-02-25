require 'saml_idp/hashable'
module SamlIdp
  class AuthnRequest
    attr_accessor :raw
  
    delegate :xpath, to: :document
    private :xpath

    def initialize(raw = "", sp_config)
      self.sp_config = sp_config
      self.raw = raw
    end

    def document
      @document ||= Saml::XML::Document.parse raw
    end

    def errors
      @errors ||= []
    end

    def valid?
      # No acceptable AssertionConsumerServiceURL, either configure them via config.service_provider.response_hosts or match to your metadata_url host
      if !service_provider.acs_urls.include?(acs_url)
        @errors.push(:unknown_acs_url)
        return false
      end
    end

    # Only supporting name id policy and ommiting saml:Conditions, RequestedAuthnContext, Scoping
    # Because those are not commonly uses for modern browser SSO
    def name_id_policy
      xpath(
        "//samlp:AuthnRequest/samlp:NameIDPolicy",
        saml: assertion
      ).reduce({}) do |hash, el|
        hash[:format] = el["Format"]
        hash[:sp_name_qualifier] = el["SPNameQualifier"]
        hash[:allow_create] = el["AllowCreate"]
        hash
      end
    end

    def issuer
      @_issuer ||= xpath("//saml:Issuer", saml: assertion).first.try(:content)
    end
    hashable :issuer

    def force_authn
      @force_authn ||= xpath("//samlp:AuthnRequest/@ForceAuthn", saml: assertion).first.try(:content).to_s
    end
    hashable :force_authn

    def is_passive
      @is_passive ||= xpath("//samlp:AuthnRequest/@IsPassive", saml: assertion).first.try(:content).to_s
    end
    hashable :is_passive

    def protocol_binding
      @protocol_binding ||= xpath("//samlp:AuthnRequest/@ProtocolBinding", saml: assertion).first.try(:content).to_s
    end
    hashable :protocol_binding

    def acs_index
      @acs_index ||= xpath("//samlp:AuthnRequest/@AssertionConsumerServiceIndex", saml: assertion).first.try(:content).to_i
    end
    hashable :acs_index

    def acs_url
      @acs_url ||= xpath("//samlp:AuthnRequest/@AssertionConsumerServiceURL", saml: assertion).first.try(:content).to_s
    end
    hashable :acs_url

    def attr_consuming_service_index
      @acs_url ||= xpath("//samlp:AuthnRequest/@AttributeConsumingServiceIndex", saml: assertion).first.try(:content).to_i
    end
    hashable :attr_consuming_service_index

    def provider_name
      @acs_url ||= xpath("//samlp:AuthnRequest/@ProviderName", saml: assertion).first.try(:content).to_i
    end
    hashable :provider_name

    def authn_context_node
      @_authn_context_node ||= xpath("//samlp:AuthnRequest/samlp:RequestedAuthnContext/saml:AuthnContextClassRef",
        samlp: samlp,
        saml: assertion).first
    end
    private :authn_context_node

    def assertion
      Saml::XML::Namespaces::ASSERTION
    end
    private :assertion

    def samlp
      Saml::XML::Namespaces::PROTOCOL
    end
    private :samlp
  end
end
