require 'spec_helper'
module SamlIdp
  describe SpConfig do
    subject { described_class.new attributes }
    let(:attributes) { {} }

    it { should respond_to :fingerprint }
    it { should respond_to :metadata_url }
    it { should_not be_valid }

    describe "with attributes" do
      let(:attributes) { { fingerprint: fingerprint, metadata_url: metadata_url } }
      let(:fingerprint) { Default::FINGERPRINT }
      let(:metadata_url) { "http://localhost:3000/metadata" }

      it "has a valid fingerprint" do
        expect(subject.fingerprint).to eq(fingerprint)
      end

      it "has a valid metadata_url" do
        expect(subject.metadata_url).to eq(metadata_url)
      end

      it { should be_valid }
    end
  end
end
