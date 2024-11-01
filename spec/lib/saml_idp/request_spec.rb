require 'spec_helper'

RSpec.describe SamlIdp::Request, type: :model do
  let(:valid_saml_request) { make_saml_request("https://foo.example.com/saml/consume", true) }
  let(:valid_logout_request) { make_saml_sp_slo_request(security_options: { embed_sign: true })['SAMLRequest'] }
  let(:invalid_saml_request) { "invalid_saml_request" }
  let(:external_attributes) { { saml_request: valid_saml_request, relay_state: "state" } }

  describe ".from_deflated_request" do
    context "when request is valid and deflated" do
      it "inflates and decodes the request" do
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect { Saml::XML::Document.parse(request.raw_xml) }.not_to raise_error
      end
    end

    context "when request is invalid" do
      it "returns an empty inflated string" do
        request = SamlIdp::Request.from_deflated_request(nil)
        expect(request.raw_xml).to eq("")
      end
    end
  end

  describe "#logout_request?" do
    it "returns true for a valid logout request" do
      request = SamlIdp::Request.from_deflated_request(valid_logout_request)
      expect(request.logout_request?).to be true
    end

    it "returns false for a non-logout request" do
      request = SamlIdp::Request.from_deflated_request(valid_saml_request)
      expect(request.logout_request?).to be false
    end
  end

  describe "#authn_request?" do
    it "returns true for a valid authn request" do
      request = SamlIdp::Request.from_deflated_request(valid_saml_request)
      expect(request.authn_request?).to be true
    end

    it "returns false for a non-authn request" do
      request = SamlIdp::Request.from_deflated_request(valid_logout_request)
      expect(request.authn_request?).to be false
    end
  end

  describe "#valid?" do
    let(:sp_issuer) { "test_issuer" }
    let(:valid_service_provider) do 
      instance_double(
        "SamlIdp::ServiceProvider",
        valid?: true,
        acs_url: 'https://foo.example.com/saml/consume',
        current_metadata: instance_double("Metadata", sign_authn_request?: true),
        assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
        sign_authn_request: true,
        acceptable_response_hosts: ["foo.example.com"],
        cert: sp_x509_cert,
        fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert, :sha256),
      )
    end
    
    before do
      allow_any_instance_of(SamlIdp::Request).to receive(:service_provider).and_return(valid_service_provider)
      allow_any_instance_of(SamlIdp::Request).to receive(:issuer).and_return(sp_issuer)
    end

    context "when the request is valid" do
      it "returns true for a valid authn request" do
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)
        expect(request.errors).to be_empty
        expect(request.valid?).to be true
      end

      it "returns true for a valid logout request" do
        request = SamlIdp::Request.from_deflated_request(valid_logout_request)
        expect(request.errors).to be_empty
        expect(request.valid?).to be true
      end
    end

    context 'when signature provided as external param' do
      let!(:uri_query) { make_saml_sp_slo_request(security_options: { embed_sign: false }) }
      let(:raw_saml_request) { uri_query['SAMLRequest'] }
      let(:relay_state) { uri_query['RelayState'] }
      let(:siging_algorithm) { uri_query['SigAlg'] }
      let(:signature) { uri_query['Signature'] }

      subject do
        described_class.from_deflated_request(
          raw_saml_request,
          saml_request: raw_saml_request,
          relay_state: relay_state,
          sig_algorithm: siging_algorithm,
          signature: signature
        )
      end

      it "should validate the request" do
        expect(subject.valid_external_signature?).to be true
        expect(subject.errors).to be_empty
      end

      it "should collect errors when the signature is invalid" do
        allow(subject).to receive(:valid_external_signature?).and_return(false)
        expect(subject.valid?).to eq(false)
        expect(subject.errors).to include(:invalid_external_signature)
      end
    end

    context "when the service provider is invalid" do
      it "returns false and logs an error" do
        allow_any_instance_of(SamlIdp::Request).to receive(:service_provider?).and_return(false)
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect(request.valid?).to be false
        expect(request.errors).to include(:sp_not_found)
      end
    end

    context "when empty certificate for authn request validation" do
      let(:valid_service_provider) do 
        instance_double(
          "SamlIdp::ServiceProvider",
          valid?: true,
          acs_url: 'https://foo.example.com/saml/consume',
          current_metadata: instance_double("Metadata", sign_authn_request?: true),
          assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
          sign_authn_request: true,
          acceptable_response_hosts: ["foo.example.com"],
          cert: nil,
          fingerprint: nil,
        )
      end
      it "returns false and logs an error" do
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect(request.valid?).to be false
        expect(request.errors).to include(:empty_certificate)
      end
    end

    context "when empty certificate for logout validation" do
      let(:valid_service_provider) do 
        instance_double(
          "SamlIdp::ServiceProvider",
          valid?: true,
          acs_url: 'https://foo.example.com/saml/consume',
          current_metadata: instance_double("Metadata", sign_authn_request?: true),
          assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
          sign_authn_request: true,
          acceptable_response_hosts: ["foo.example.com"],
          cert: nil,
          fingerprint: nil,
        )
      end

      before do
        allow_any_instance_of(SamlIdp::Request).to receive(:authn_request?).and_return(false)
        allow_any_instance_of(SamlIdp::Request).to receive(:logout_request?).and_return(true)
      end

      it "returns false and logs an error" do
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect(request.valid?).to be false
        expect(request.errors).to include(:empty_certificate)
      end
    end

    context "when both authn and logout requests are present" do
      it "returns false and logs an error" do
        allow_any_instance_of(SamlIdp::Request).to receive(:authn_request?).and_return(true)
        allow_any_instance_of(SamlIdp::Request).to receive(:logout_request?).and_return(true)
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect(request.valid?).to be false
        expect(request.errors).to include(:unaccepted_request)
      end
    end

    context "when the signature is invalid" do
      it "returns false and logs an error" do
        allow_any_instance_of(SamlIdp::Request).to receive(:valid_signature?).and_return(false)
        allow_any_instance_of(SamlIdp::Request).to receive(:log)
        request = SamlIdp::Request.from_deflated_request(valid_saml_request)

        expect(request.valid?).to be false
        expect(request.errors).to include(:invalid_embedded_signature)
      end
    end
  end
end
