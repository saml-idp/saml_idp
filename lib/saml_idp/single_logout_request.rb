require 'saml_idp/hashable'
module SamlIdp
  class SingleLogoutRequest
    attr_accessor :raw

    delegate :xpath, to: :document
    private :xpath

    def initialize(raw = "")
      self.raw = raw
    end

    def document
      @document ||= Saml::XML::Document.parse raw
    end

    def valid?
      true
    end

    def name_id
      @_name_id ||= xpath("//saml:NameID", saml: assertion).first.try(:content)
    end
    hashable :name_id

    # Not supported yet
    def base_id
      @_base_id ||= xpath("//saml:BaseID", saml: assertion).first.try(:content)
    end
    hashable :base_id

    # Not supported yet
    def encrypted_id
      @_name_id ||= xpath("//saml:EncryptedID", saml: assertion).first.try(:content)
    end
    hashable :encrypted_id

    def session_index
      @_session_index ||= xpath("//samlp:SessionIndex", samlp: samlp).first.try(:content)
    end
    hashable :session_index

    def sp_name_qualifier
      @_sp_name_qualifier ||= xpath("//saml:NameID/@SPNameQualifier", saml: assertion).first.try(:content).to_s
    end
    hashable :sp_name_qualifier

    def samlp
      Saml::XML::Namespaces::PROTOCOL
    end
    private :samlp

    def assertion
      Saml::XML::Namespaces::ASSERTION
    end
    private :assertion
  end
end
