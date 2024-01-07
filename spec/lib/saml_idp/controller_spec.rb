# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  def render(*)
  end

  def head(*)
  end

  def raw_saml_request
    @raw_saml_request
  end

  def sp_config_hash
    @sp_config_hash
  end

  def sp_raw_metadata
    @sp_raw_metadata
  end

  def idp_config_hash
    @idp_config_hash
  end

  context "SAML AuthnRequest Request" do
    before do
      @idp_config_hash = {
        base_url: 'http://idp.com/saml/idp',
        x509_certificate: SamlIdp::Default::X509_CERTIFICATE,
        secret_key: SamlIdp::Default::SECRET_KEY,
        password: nil,
        algorithm: :sha256,
        organization_name: 'idp.com',
        organization_url: 'http://idp.com',
        single_service_post_location: 'http://idp.com/saml/idp/sso',
        single_service_redirect_location: 'http://idp.com/saml/idp/sso',
        single_logout_service_post_location: 'http://idp.com/saml/idp/logout',
        single_logout_service_redirect_location: 'http://idp.com/saml/idp/logout',
        attribute_service_location: 'http://idp.com/saml/idp/attribute',
        name_id_formats: {
            "1.1" => {
            email_address: -> { 'some_email'},
          }
        }
      }
    end

    context "when valid SP initiated request provided" do
      let(:requested_saml_acs_url) { "https://foo.example.com/saml/consume" }

      before do
        @raw_saml_request = make_saml_request(requested_saml_acs_url)
        @sp_raw_metadata = generate_sp_metadata('https://foo.example.com/saml/consume', false)
      end

      it "should find the SAML ACS URL" do
        expect(validate_saml_request).to eq(true)
        expect(saml_request.error_msg).to be_empty
        expect(saml_request.acs_url).to eq(requested_saml_acs_url)
      end
    end
  end

  context "When SP metadata required to validate auth request signature" do
    let(:signed_doc) { SamlIdp::XMLSecurity::SignedDocument.new(raw_saml_request) }
    before do
      @sp_config = nil
      @sp_raw_metadata = generate_sp_metadata('https://foo.example.com/saml/consume', true)
      @raw_saml_request = make_saml_request("https://foo.example.com/saml/consume", true)
      allow(signed_doc).to receive(:validate).and_return(true)
      allow(SamlIdp::XMLSecurity::SignedDocument).to receive(:new).and_return(signed_doc)
    end

    it 'should call xml signature validation method' do
      validate_saml_request
      expect(signed_doc).to have_received(:validate).once
    end

    it 'should successfully validate signature' do
      expect(validate_saml_request).to eq(true)
    end
  end

  context "SAML Responses" do
    let(:principal) { double email_address: "foo@example.com" }
    let(:idp_setting) do
      {
        base_url: 'http://idp.com',
        x509_certificate: SamlIdp::Default::X509_CERTIFICATE,
        secret_key: SamlIdp::Default::SECRET_KEY,
        password: nil,
        algorithm: :sha256,
        organization_name: 'idp.com',
        organization_url: 'http://idp.com',
        single_service_post_location: 'http://idp.com/saml/idp/sso',
        single_service_redirect_location: 'http://idp.com/saml/idp/sso',
        single_logout_service_post_location: 'http://idp.com/saml/idp/logout',
        single_logout_service_redirect_location: 'http://idp.com/saml/idp/logout',
        attribute_service_location: 'http://idp.com/saml/idp/attribute',
        name_id_formats: {
            "1.1" => {
            email_address: -> (principal) { principal.email_address },
          }
        }
      }
    end

    let(:sp_setting) do
      {
        entity_id: 'http://example.com',
        assertion_consumer_services: [
          { 
            binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            location: 'https://example.com/saml/consume',
            default: true
          }
        ]
      }
    end

    let(:sp_gem_config) do
      {
        assertion_consumer_service_url: sp_setting[:assertion_consumer_services].first[:location],
        issuer: sp_setting[:entity_id],
        idp_sso_target_url: idp_setting[:single_service_post_location],
        assertion_consumer_logout_service_url: 'https://foo.example.com/saml/logout',
        idp_cert_fingerprint: SamlIdp::Default::FINGERPRINT,
        name_identifier_format: SamlIdp::Default::NAME_ID_FORMAT
      }
    end

    before do
      @idp_config_hash = idp_setting
      @sp_config_hash = sp_setting
    end

    subject do
      saml_response = encode_response(principal)
      ruby_saml_settings = OneLogin::RubySaml::Settings.new(sp_gem_config)
      OneLogin::RubySaml::Response.new(saml_response, settings: ruby_saml_settings)
    end

    context "unsolicited (IdP initiated) Response" do
      it "should create a SAML Response" do
        expect(subject.name_id).to eq("foo@example.com")
        expect(subject.issuers.first).to eq("http://idp.com")
        expect(subject.is_valid?).to be_truthy
      end
    end

    context "solicited (SP initiated) Response" do
      before do
        @raw_saml_request = make_saml_request
        expect(validate_saml_request).to eq(true)
      end

      it "should create a SAML Response" do
        expect(subject.name_id).to eq("foo@example.com")
        expect(subject.issuers.first).to eq("http://example.com")
        expect(subject.is_valid?).to be_truthy
      end
    end

    context "With encryption config" do
      let (:encryption_opts) do
        {
          cert: SamlIdp::Default::X509_CERTIFICATE,
          block_encryption: 'aes256-cbc',
          key_transport: 'rsa-oaep-mgf1p',
        }
      end

      before do
        @idp_config_hash[:encryption_config] = encryption_opts
        sp_gem_config[:private_key] = SamlIdp::Default::SECRET_KEY
      end

      it "should encrypt SAML Response assertion" do
        expect(subject.document.to_s).to_not match("foo@example.com")
        expect(subject.decrypted_document.to_s).to match("foo@example.com")
        expect(subject.name_id).to eq("foo@example.com")
        expect(subject.issuers.first).to eq("http://idp.com")
        expect(subject.is_valid?).to be_truthy
      end
    end

    [:sha1, :sha256, :sha384, :sha512].each do |algorithm_name|
      context "Signature with #{algorithm_name} algorithm" do
        before do
          @idp_config_hash[:raw_algorithm] = algorithm_name
          @raw_saml_request = make_saml_request
          expect(validate_saml_request).to eq(true)
        end
        
        it "should create a SAML Response using the #{algorithm_name} algorithm" do
          expect(subject.name_id).to eq("foo@example.com")
          expect(subject.issuers.first).to eq("http://idp.com")
          expect(subject.is_valid?).to be_truthy
        end
      end
    end

    context "Single logout request" do
      it "should create a SAML Logout Response" do
        @raw_saml_request = make_saml_logout_request
        expect(validate_saml_request).to eq(true)
        expect(saml_request.logout_request?).to eq true
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Logoutresponse.new(saml_response, saml_settings)
        expect(response.validate).to eq(true)
        expect(response.issuer).to eq("http://example.com")
      end
    end
  end
end
