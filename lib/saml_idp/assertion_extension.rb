require "builder"

module SamlIdp
  # Base class for extending the SAML 2.0 assertion at defined extension points.
  # Aligns with OASIS SAML 2.0 Core: SubjectConfirmationData (2.4.1.2) allows arbitrary
  # elements/attributes; AuthnContext (2.7.2.2) allows AuthnContextDecl by value.
  # See docs/assertion_extension_saml_spec_analysis.md for spec analysis.
  class AssertionExtension
    SUBJECT_CONFIRMATION_DATA_EXTENSION_POINT = "SubjectConfirmationData"
    AUTHN_CONTEXT_DECL_EXTENSION_POINT = "AuthnContextDecl"

    attr_accessor :extension_point

    def initialize(extension_point)
      self.extension_point = extension_point
    end

    # Subclasses must implement build(context). The context is a Builder block for
    # either SubjectConfirmation (for SubjectConfirmationData) or AuthnContext (for AuthnContextDecl).
    #
    # For SUBJECT_CONFIRMATION_DATA: emit SubjectConfirmationData with standard attributes
    # (NotOnOrAfter, Recipient, InResponseTo when using bearer) and add custom elements inside it.
    #
    # Example (AuthnContextDecl extension):
    #
    # context.AuthnContextDecl do |builder|
    #   builder.AuthenticationContextDeclaration xmlns: "urn:my_org:saml:2.0:Device" do |context|
    #     context.Extension do |ext|
    #       ext.Device xmlns: "urn:my_org:saml:2.0:ZeroTrust", ID: "f659c992-2b3d-4e2d-a155-6d32161e6754" do |device|
    #         device.Trust do |trust|
    #           trust.Data Name: "Managed", Value: true
    #           trust.Data Name: "Compliant", Value: true
    #         end
    #       end
    #     end
    #   end
    # end
    def build(context)
      raise "#{self.class} must implement build method"
    end
  end
end
