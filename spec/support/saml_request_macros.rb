require 'saml_idp/logout_request_builder'

module SamlRequestMacros
  def make_saml_request(requested_saml_acs_url = "https://foo.example.com/saml/consume", enable_secure_options = false)
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_url = auth_request.create_params(saml_settings(requested_saml_acs_url, enable_secure_options))
    auth_url['SAMLRequest']
  end

  def make_saml_logout_request(requested_saml_logout_url = 'https://foo.example.com/saml/logout')
    request_builder = SamlIdp::LogoutRequestBuilder.new(
      'some_response_id',
      'http://example.com',
      requested_saml_logout_url,
      'some_name_id',
      OpenSSL::Digest::SHA256
    )
    Base64.strict_encode64(request_builder.signed)
  end

  def generate_sp_metadata(saml_acs_url = "https://foo.example.com/saml/consume", enable_secure_options = false)
    sp_metadata = OneLogin::RubySaml::Metadata.new
    sp_metadata.generate(saml_settings(saml_acs_url, enable_secure_options), true)
  end

  def saml_settings(saml_acs_url = "https://foo.example.com/saml/consume", enable_secure_options = false)
    settings = OneLogin::RubySaml::Settings.new
    settings.assertion_consumer_service_url = saml_acs_url
    settings.issuer = "http://example.com/issuer"
    settings.idp_sso_target_url = "http://idp.com/saml/idp"
    settings.assertion_consumer_logout_service_url = 'https://foo.example.com/saml/logout'
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    add_securty_options(settings) if enable_secure_options
    settings
  end

  def add_securty_options(settings, authn_requests_signed: true, 
                                    embed_sign: true, 
                                    logout_requests_signed: true, 
                                    logout_responses_signed: true,
                                    digest_method: XMLSecurity::Document::SHA256,
                                    signature_method: XMLSecurity::Document::RSA_SHA256,
                                    assertions_signed: true)
    # Security section
    settings.idp_cert = SamlIdp::Default::X509_CERTIFICATE
    # Signed embedded singature
    settings.security[:authn_requests_signed] = authn_requests_signed
    settings.security[:embed_sign] = embed_sign
    settings.security[:logout_requests_signed] = logout_requests_signed
    settings.security[:logout_responses_signed] = logout_responses_signed
    settings.security[:metadata_signed] = digest_method
    settings.security[:digest_method] = digest_method
    settings.security[:signature_method] = signature_method
    settings.security[:want_assertions_signed] = assertions_signed
    settings.private_key = sp_pv_key
    settings.certificate = sp_x509_cert
  end

  def idp_configure(saml_acs_url = "https://foo.example.com/saml/consume", enable_secure_options = false)
    SamlIdp.configure do |config|
      config.x509_certificate = SamlIdp::Default::X509_CERTIFICATE
      config.secret_key = SamlIdp::Default::SECRET_KEY
      config.password = nil
      config.algorithm = :sha256
      config.organization_name = 'idp.com'
      config.organization_url = 'http://idp.com'
      config.base_saml_location = 'http://idp.com/saml/idp'
      config.single_logout_service_post_location = 'http://idp.com/saml/idp/logout'
      config.single_logout_service_redirect_location = 'http://idp.com/saml/idp/logout'
      config.attribute_service_location = 'http://idp.com/saml/idp/attribute'
      config.single_service_post_location = 'http://idp.com/saml/idp/sso'
      config.name_id.formats = SamlIdp::Default::NAME_ID_FORMAT
      config.service_provider.metadata_persister = lambda { |_identifier, _service_provider|
        raw_metadata = generate_sp_metadata(saml_acs_url, enable_secure_options)
        SamlIdp::IncomingMetadata.new(raw_metadata).to_h
      }
      config.service_provider.persisted_metadata_getter = lambda { |_identifier, _settings|
        raw_metadata = generate_sp_metadata(saml_acs_url, enable_secure_options)
        SamlIdp::IncomingMetadata.new(raw_metadata).to_h
      }
      config.service_provider.finder = lambda { |_issuer_or_entity_id|
        {
          response_hosts: [URI(saml_acs_url).host],
          acs_url: saml_acs_url,
          cert: sp_x509_cert,
          fingerprint: SamlIdp::Fingerprint.certificate_digest(sp_x509_cert)
        }
      }
    end
  end

  def decode_saml_request(saml_request)
    decoded_request = Base64.decode64(saml_request)
    begin
      # Try to decompress, since SAMLRequest might be compressed
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(decoded_request)
    rescue Zlib::DataError
      # If it's not compressed, just return the decoded request
      decoded_request
    end
  end

  def print_pretty_xml(xml_string)
    doc = REXML::Document.new xml_string
    outbuf = ""
    doc.write(outbuf, 1)
    puts outbuf
  end
end
