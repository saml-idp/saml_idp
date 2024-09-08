require 'spec_helper'
module SamlIdp
  describe Request do
    let(:issuer) { 'localhost:3000' }
    let(:raw_authn_request) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    describe "deflated request" do
      let(:deflated_request) { Base64.encode64(Zlib::Deflate.deflate(raw_authn_request, 9)[2..-5]) }

      subject { described_class.from_deflated_request deflated_request }

      it "inflates" do
        expect(subject.request_id).to eq("_af43d1a0-e111-0130-661a-3c0754403fdb")
      end

      it "handles invalid SAML" do
        req = described_class.from_deflated_request "bang!"
        expect(req.valid?).to eq(false)
        expect(req.erros).to include(:sp_not_found)
      end
    end

    describe "authn request" do
      subject { described_class.new raw_authn_request }

      it "has a valid request_id" do
        expect(subject.request_id).to eq("_af43d1a0-e111-0130-661a-3c0754403fdb")
      end

      it "has a valid acs_url" do
        expect(subject.acs_url).to eq("http://localhost:3000/saml/consume")
      end

      it "has a valid service_provider" do
        expect(subject.service_provider).to be_a ServiceProvider
      end

      it "should return acs_url for response_url" do
        expect(subject.response_url).to eq(subject.acs_url)
      end

      it "collects errors when service_provider is not found" do
        allow(subject).to receive(:service_provider?).and_return(false)
        expect(subject.valid?).to eq(false)
        expect(subject.erros).to include(:sp_not_found)
      end

      it "collects errors when no request type is provided" do
        allow(subject).to receive(:authn_request?).and_return(false)
        allow(subject).to receive(:logout_request?).and_return(false)
        expect(subject.valid?).to eq(false)
        expect(subject.erros).to include(:unaccepted_request)
      end

      context 'the issuer is empty' do
        let(:issuer) { nil }

        it 'is invalid and collects an error' do
          expect(subject.valid?).to eq(false)
          expect(subject.erros).to include(:sp_not_found)
        end
      end

      context "when signature is invalid" do
        before do
          allow(subject).to receive(:valid_signature?).and_return(false)
        end

        it "collects invalid signature error" do
          expect(subject.valid?).to eq(false)
          expect(subject.erros).to include(:invalid_embedded_signature)
        end
      end
    end

    describe "logout request" do
      context 'when POST binding' do
        let(:raw_logout_request) do
          "<LogoutRequest ID='_some_response_id' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'>
          <Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>http://example.com</Issuer>
          <NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'>some_name_id</NameID>
          <SessionIndex>abc123index</SessionIndex></LogoutRequest>"
        end

        subject { described_class.new raw_logout_request }

        it "has a valid request_id" do
          expect(subject.request_id).to eq('_some_response_id')
        end

        it "should be flagged as a logout_request" do
          expect(subject.logout_request?).to eq(true)
        end

        it "should have a valid name_id" do
          expect(subject.name_id).to eq('some_name_id')
        end

        it "should have a session index" do
          expect(subject.session_index).to eq('abc123index')
        end

        it "should have a valid issuer" do
          expect(subject.issuer).to eq('http://example.com')
        end

        it "fetches internal request" do
          expect(subject.request['ID']).to eq(subject.request_id)
        end

        it "should return logout_url for response_url" do
          expect(subject.response_url).to eq(subject.logout_url)
        end

        it "is valid when all conditions are met" do
          expect(subject.valid?).to eq(true)
          expect(subject.erros).to be_empty
        end
      end

      context 'when there are errors in the logout request' do
        let(:raw_logout_request) do
          "<LogoutRequest ID='' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'>
          <Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'></Issuer>
          <NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'></NameID>
          <SessionIndex></SessionIndex></LogoutRequest>"
        end

        subject { described_class.new raw_logout_request }

        it "should collect errors when there is an empty request_id" do
          expect(subject.valid?).to eq(false)
          expect(subject.erros).to include(:sp_not_found)
        end

        it "should collect errors when there is no valid name_id" do
          expect(subject.name_id).to be_nil
          expect(subject.erros).to include(:invalid_name_id)
        end

        it "should collect errors when the issuer is missing" do
          expect(subject.issuer).to be_nil
          expect(subject.erros).to include(:invalid_issuer)
        end

        it "should be flagged as invalid" do
          expect(subject.valid?).to eq(false)
          expect(subject.erros).to include(:invalid_request)
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
          allow(ServiceProvider).to receive(:new).and_return(
            ServiceProvider.new(
              issuer: "http://example.com/issuer",
              cert: sp_x509_cert,
              fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert),
            )
          )
          expect(subject.valid_external_signature?).to be true
          expect(subject.erros).to be_empty
        end

        it "should collect errors when the signature is invalid" do
          allow(subject).to receive(:valid_external_signature?).and_return(false)
          expect(subject.valid?).to eq(false)
          expect(subject.erros).to include(:invalid_external_signature)
        end
      end
    end
  end
end
