require 'spec_helper'
module SamlIdp
  describe SpConfig do
    let(:attributes) { { entity_id: entity_id, assertion_consumer_services: assertion_consumer_services } }

    subject { described_class.new attributes }

    describe "with attributes" do
      let(:entity_id) { "http://localhost:3000/idp" }
      let(:assertion_consumer_services) { 
        [
          { 
            binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            location: "http://sp.example.com/saml",
            default: true
          }
        ]
       }

      it "has a valid entity_id" do
        expect(subject.entity_id).to eq(entity_id)
      end

      it "has a valid assertion_consumer_services" do
        expect(subject.assertion_consumer_services).to eq(assertion_consumer_services)
      end

      it { should be_valid }
    end
  end
end
