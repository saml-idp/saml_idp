require 'spec_helper'
require 'saml_idp/logout_response_builder'

module SamlIdp
  describe LogoutResponseBuilder do
    before do
      Timecop.freeze(Time.local(1990))
    end

    after do
      Timecop.return
    end

    let(:response_id) { 'some_response_id' }
    let(:issuer_uri) { 'http://example.com' }
    let(:saml_slo_url) { 'http://localhost:3000/saml/logout' }
    let(:request_id) { 'some_request_id' }
    let(:algorithm) { OpenSSL::Digest::SHA256 }

    subject do
      described_class.new(
        response_id: response_id,
        issuer_uri: issuer_uri,
        saml_slo_url: saml_slo_url,
        saml_request_id: request_id,
        algorithm: algorithm,
        public_cert: SamlIdp::Default::X509_CERTIFICATE,
        private_key: SamlIdp::Default::SECRET_KEY
      )
    end

    it "is a valid LogoutResponse" do
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        logout_response = OneLogin::RubySaml::Logoutresponse.new(
          subject.encoded,
          saml_settings('localhost:3000')
        )
        logout_response.soft = false
        expect(logout_response.validate).to eq true
      end
    end
  end
end
