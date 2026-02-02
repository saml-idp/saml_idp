require 'spec_helper'

module SamlIdp
  describe AssertionExtension do
    describe "extension point constants" do
      it "defines SUBJECT_CONFIRMATION_DATA_EXTENSION_POINT" do
        expect(described_class::SUBJECT_CONFIRMATION_DATA_EXTENSION_POINT).to eq("SubjectConfirmationData")
      end

      it "defines AUTHN_CONTEXT_DECL_EXTENSION_POINT" do
        expect(described_class::AUTHN_CONTEXT_DECL_EXTENSION_POINT).to eq("AuthnContextDecl")
      end
    end

    describe "#initialize" do
      it "sets extension_point" do
        extension = described_class.new(described_class::AUTHN_CONTEXT_DECL_EXTENSION_POINT)
        expect(extension.extension_point).to eq("AuthnContextDecl")
      end
    end

    describe "#build" do
      it "raises when not overridden" do
        extension = described_class.new(described_class::AUTHN_CONTEXT_DECL_EXTENSION_POINT)
        context = double("builder context")
        expect { extension.build(context) }.to raise_error(/#{described_class} must implement build method/)
      end
    end

    describe "subclass implementing build" do
      let(:extension_class) do
        Class.new(described_class) do
          def build(context)
            context.CustomElement "custom_value"
          end
        end
      end

      it "invokes build with the builder context" do
        extension = extension_class.new(described_class::AUTHN_CONTEXT_DECL_EXTENSION_POINT)
        context = double("builder context")
        expect(context).to receive(:CustomElement).with("custom_value")
        extension.build(context)
      end
    end
  end
end
