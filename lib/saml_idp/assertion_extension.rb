require "builder"

module SamlIdp
  class AssertionExtension
    SUBJECT_CONFIRMATION_DATA_EXTENSION_POINT = "SubjectConfirmationData"
    AUTHN_CONTEXT_DECL_EXTENSION_POINT = "AuthnContextDecl"

    attr_accessor :extension_point

    def initialize(extension_point)
      self.extension_point = extension_point
    end

    # this is an abstract base class.
    def build(context)
      raise "#{self.class} must implement build method"
    end
  end
end
