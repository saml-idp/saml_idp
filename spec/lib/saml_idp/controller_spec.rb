# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  def render(*)
  end

  def head(*)
  end

  def params
    @params ||= {}
  end

  it "should find the SAML ACS URL" do
    requested_saml_acs_url = "https://example.com/saml/consume"
    params[:SAMLRequest] = make_saml_request(requested_saml_acs_url)
    expect(validate_saml_request).to eq(true)
    expect(saml_acs_url).to eq(requested_saml_acs_url)
  end

  context "When SP metadata required to validate auth request signature" do
    before do
      idp_configure("https://foo.example.com/saml/consume", true)
      params[:SAMLRequest] = make_saml_request("https://foo.example.com/saml/consume", true)
    end

    it 'SP metadata sign_authn_request attribute should be true' do
      # Signed auth request will be true in the metadata
      expect(SamlIdp.config.service_provider.persisted_metadata_getter.call(nil,nil)[:sign_authn_request]).to eq(true)
    end

    it 'should call xml signature validation method' do
      signed_doc = SamlIdp::XMLSecurity::SignedDocument.new(decode_saml_request(params[:SAMLRequest]))
      allow(signed_doc).to receive(:validate).and_return(true)
      allow(SamlIdp::XMLSecurity::SignedDocument).to receive(:new).and_return(signed_doc)
      validate_saml_request
      expect(signed_doc).to have_received(:validate).once
    end

    it 'should successfully validate signature' do
      expect(validate_saml_request).to eq(true)
    end
  end

  context "SAML Responses" do
    let(:principal) { double email_address: "foo@example.com" }
    let (:encryption_opts) do
      {
        cert: SamlIdp::Default::X509_CERTIFICATE,
        block_encryption: 'aes256-cbc',
        key_transport: 'rsa-oaep-mgf1p',
      }
    end

    context "unsolicited Response" do
      it "should create a SAML Response" do
        saml_response = encode_response(principal, { audience_uri: 'http://example.com/issuer', issuer_uri: 'http://example.com', acs_url: 'https://foo.example.com/saml/consume' })
        response = OneLogin::RubySaml::Response.new(saml_response)
        expect(response.name_id).to eq("foo@example.com")
        expect(response.issuers.first).to eq("http://example.com")
        response.settings = saml_settings
        expect(response.is_valid?).to be_truthy
      end
    end

    context "solicited Response" do
      before(:each) do
        params[:SAMLRequest] = make_saml_request
        expect(validate_saml_request).to eq(true)
      end

      it "should create a SAML Response" do
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Response.new(saml_response)
        expect(response.name_id).to eq("foo@example.com")
        expect(response.issuers.first).to eq("http://example.com")
        response.settings = saml_settings
        expect(response.is_valid?).to be_truthy
      end

      it "should create a SAML Logout Response" do
        params[:SAMLRequest] = make_saml_logout_request
        expect(validate_saml_request).to eq(true)
        expect(saml_request.logout_request?).to eq true
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Logoutresponse.new(saml_response, saml_settings)
        expect(response.validate).to eq(true)
        expect(response.issuer).to eq("http://example.com")
      end

      it "should by default create a SAML Response with a signed assertion" do
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Response.new(saml_response)
        response.settings = saml_settings("https://foo.example.com/saml/consume", true)
        expect(response.is_valid?).to be_truthy
      end

      [:sha1, :sha256, :sha384, :sha512].each do |algorithm_name|
        it "should create a SAML Response using the #{algorithm_name} algorithm" do
          self.algorithm = algorithm_name
          saml_response = encode_response(principal)
          response = OneLogin::RubySaml::Response.new(saml_response)
          expect(response.name_id).to eq("foo@example.com")
          expect(response.issuers.first).to eq("http://example.com")
          response.settings = saml_settings
          expect(response.is_valid?).to be_truthy
        end

        it "should encrypt SAML Response assertion" do
          self.algorithm = algorithm_name
          saml_response = encode_response(principal, encryption: encryption_opts)
          resp_settings = saml_settings
          resp_settings.private_key = SamlIdp::Default::SECRET_KEY
          response = OneLogin::RubySaml::Response.new(saml_response, settings: resp_settings)
          expect(response.document.to_s).to_not match("foo@example.com")
          expect(response.decrypted_document.to_s).to match("foo@example.com")
          expect(response.name_id).to eq("foo@example.com")
          expect(response.issuers.first).to eq("http://example.com")
          expect(response.is_valid?).to be_truthy
        end
      end
    end
  end
end
