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

      it "has a valid service_provider" do
        expect(subject.service_provider).to be_truthy
      end

      it "has a valid issuer" do
        expect(subject.issuer).to eq("localhost:3000")
      end

      it "has a valid valid_signature" do
        expect(subject.valid_signature?).to be_truthy
      end

      it "should return acs_url for response_url" do
        expect(subject.response_url).to eq(subject.acs_url)
      end

      it "is a authn request" do
        expect(subject.authn_request?).to eq(true)
      end

      it "fetches internal request" do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'has a valid authn context' do
        expect(subject.requested_authn_context).to eq('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')
      end

      context 'the issuer is empty' do
        let(:issuer) { nil }
        let(:logger) { ->(msg) { puts msg } }

        before do
          allow(SamlIdp.config).to receive(:logger).and_return(logger)
        end

        it 'is invalid' do
          expect(subject.issuer).to_not eq('')
          expect(subject.issuer).to be_nil
          expect(subject.valid?).to eq(false)
        end

        context 'a Ruby Logger is configured' do
          let(:logger) { Logger.new($stdout) }

          before do
            allow(logger).to receive(:info)
          end

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:info).with('Unable to find service provider for issuer ')
          end
        end

        context 'a Logger-like logger is configured' do
          let(:logger) do
            Class.new {
              def info(msg); end
            }.new
          end

          before do
            allow(logger).to receive(:info)
          end

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:info).with('Unable to find service provider for issuer ')
          end
        end

        context 'a logger lambda is configured' do
          let(:logger) { double }

          before { allow(logger).to receive(:call) }

          it 'logs an error message' do
            expect(subject.valid?).to be false
            expect(logger).to have_received(:call).with('Unable to find service provider for issuer ')
          end
        end
      end
    end

    describe "logout request" do
      let(:raw_logout_request) { "<LogoutRequest ID='_some_response_id' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'><Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>http://example.com</Issuer><NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'>some_name_id</NameID><SessionIndex>abc123index</SessionIndex></LogoutRequest>" }

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
    end
  end
end
