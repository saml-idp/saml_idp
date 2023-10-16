require "builder"

module SamlIdp
  class AssertionExtension
    SUBJECT_CONFIRMATION_DATA_EXTENSION_POINT = "SubjectConfirmationData"
    AUTHN_CONTEXT_DECL_EXTENSION_POINT = "AuthnContextDecl"

    attr_accessor :extension_point

    def initialize(extension_point)
      self.extension_point = extension_point
    end

    # This is an abstract base class, an example extension may look like this:
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
