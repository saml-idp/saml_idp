require 'spec_helper'
require 'xml_security'

module SamlIdp
  describe 'XmlSecurity::SignedDocument' do
    let(:xml_string) { fixture('valid_SHA256.xml', path: 'requests') }
    let(:ds_namespace) { { 'ds' => 'http://www.w3.org/2000/09/xmldsig#' } }
    let(:auth_request) { custom_saml_request }
    let(:request) { Request.from_deflated_request(auth_request) }
    let(:base64_cert_text) { saml_settings.certificate }
    let(:base64_cert) { OpenSSL::X509::Certificate.new(Base64.decode64(saml_settings.certificate)) }

    subject do
      request.send(:document).signed_document
    end

    describe '#validate_doc' do
      describe 'when softly validating' do
        before do
          allow(subject).to receive(:digests_match?).and_return false
        end

        it 'does not throw NS related exceptions' do
          expect(subject.validate_doc(base64_cert_text, true)).to be_falsey
        end

        context 'with multiple validations' do
          it 'does not raise an error' do
            expect { 2.times { subject.validate_doc(base64_cert_text, true) } }.not_to raise_error
          end
        end
      end

      describe 'when throwing errors' do
        context 'when when the certs do not match' do
          let(:wrong_cert) { remove_cert_boundaries(custom_idp_x509_cert) }

          it 'raises key validation error' do
            expect { subject.validate_doc(wrong_cert, false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Key validation error'
              )
            )
          end
        end

        context 'when the digests do not match' do
          before do
            allow(subject).to receive(:digests_match?).and_return false
          end

          it 'raises digest mismatch error' do
            expect { subject.validate_doc(base64_cert_text, false) }.to(
              raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                          'Digest mismatch')
            )
          end
        end
      end
    end

    describe '#validate' do
      describe 'errors' do
        before do
          allow(subject.document).to receive(:at_xpath).and_call_original
        end

        context 'when certificate is invalid' do
          let(:cert_element) { double Nokogiri::XML::Element }
          let(:wrong_cert) { "not-a-certificate" }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          it 'raises invalid certificate error' do
            expect { subject.validate('fingerprint', false) }.to(
              raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                          'Invalid certificate')
            )
          end
        end

        context 'when x509Certicate is missing entirely' do
          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(nil)
          end

          it 'raises validation error' do
            expect { subject.validate('fingerprint', false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Certificate element missing in response (ds:X509Certificate) and not provided in options[:cert]'
              )
            )
          end
        end

        context 'when X509 element exists but is empty ' do
          let(:cert_element) { double Nokogiri::XML::Element }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return('')
          end

          it 'returns nil' do
            expect { subject.validate('a fingerprint', false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Certificate element present in response (ds:X509Certificate) but evaluating to nil'
              )
            )
          end
        end
      end

      describe '#digest_method_algorithm' do
        subject { XMLSecurity::SignedDocument.new(xml_string) }

        let(:xml_string) { fixture('valid_no_ns.xml', path: 'requests') }
        let(:sig_element) do
          subject.document.at_xpath('//ds:Signature | //Signature', ds_namespace)
        end

        let(:ref) do
          sig_element.at_xpath('//ds:Reference | //Reference', ds_namespace)
        end

        context 'when document does not have ds namespace for Signature elements' do
          it 'returns the value in the DigestMethod node' do
            expect(subject.send(:digest_method_algorithm, ref)).to eq OpenSSL::Digest::SHA256
          end
        end

        context 'document does have ds namespace for Signature elements' do
          let(:xml_string) do
            SamlIdp::Request.from_deflated_request(custom_saml_request).raw_xml
          end

          it 'returns the value in the DigestMethod node' do
            expect(subject.send(:digest_method_algorithm, ref)).to eq OpenSSL::Digest::SHA256
          end
        end
      end

      describe 'Algorithms' do
        let(:signature_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }
        let(:digest_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }

        let(:auth_request) do
          custom_saml_request(
            security_overrides: {
              signature_method:,
              digest_method:,
            }
          )
        end

        context 'when using SHA1 as a signing algorithm' do
          let(:algorithm) { '1' }

          it 'validates using SHA1' do
            fingerprint = OpenSSL::Digest::SHA1.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be true
          end
        end

        context 'when using SHA256 as a signing algorithm' do
          let(:algorithm) { '256' }

          it 'validates using SHA256' do
            fingerprint = OpenSSL::Digest::SHA256.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be true
          end
        end

        context 'when using SHA384 as a signing algorithm' do
          let(:algorithm) { '384' }

          it 'validates using SHA384' do
            fingerprint = OpenSSL::Digest::SHA384.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be true
          end
        end

        context 'when using SHA512 as a signing algorithm' do
          let(:algorithm) { '512' }

          it 'validates using SHA512' do
            fingerprint = OpenSSL::Digest::SHA512.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be true
          end
        end
      end
    end

    describe '#validate_with_sha256' do
      context 'with an embedded request' do

        context 'when the request certificate does not match an idp certificate' do
          let(:cert_element) { double Nokogiri::XML::Element }
          let(:wrong_cert) { remove_cert_boundaries(custom_idp_x509_cert) }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          it 'raises an error' do
            expect { subject.validate_with_sha256(base64_cert) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Request certificate not valid or registered'
              )
            )
          end
        end

        context 'when the request certificate is invalid' do
          let(:cert_element) { double Nokogiri::XML::Element }
          let(:wrong_cert) { 'invalid_cert' }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          it 'raises an error' do
            expect { subject.validate_with_sha256(base64_cert) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Request certificate not valid or registered'
              )
            )
          end
        end

        context 'with different signing algorithms' do
          let(:signature_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }
          let(:digest_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }

          let(:auth_request) do
            custom_saml_request(
              security_overrides: {
                signature_method:,
                digest_method:,
              }
            )
          end

          context 'when using SHA1 as a signing algorithm' do
            let(:algorithm) { '1' }

            it 'raises an error' do
              fingerprint = OpenSSL::Digest::SHA1.new(base64_cert.to_der).hexdigest
              expect { subject.validate_with_sha256(base64_cert) }.to(
                raise_error(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Signature Algorithm needs to be SHA256'
                )
              )
            end
          end

          context 'when using SHA256 as a signing algorithm' do
            let(:algorithm) { '256' }

            it 'validate using SHA256' do
              expect(subject.validate_with_sha256(base64_cert)).to be true
            end
          end

          context 'when using SHA384 as a signing algorithm' do
            let(:algorithm) { '384' }

            it 'raises an error' do
              expect { subject.validate_with_sha256(base64_cert) }.to(
                raise_error(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Signature Algorithm needs to be SHA256'
                )
              )
            end
          end

          context 'when using SHA512 as a signing algorithm' do
            let(:algorithm) { '512' }

            it 'raises an error' do
              expect { subject.validate_with_sha256(base64_cert) }.to(
                raise_error(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Signature Algorithm needs to be SHA256'
                )
              )
            end
          end
        end
      end
    end

    describe '#extract_inclusive_namespaces' do
      context 'explicit namespace resolution' do
        it 'supports explicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default samlp saml ds xs xsi md])
        end
      end

      context 'implicit namespace resolution' do
        subject { XMLSecurity::SignedDocument.new(xml_string) }
        # using XML response to test no namespace for the InclusiveNamespaces element
        let(:xml_string) { fixture('no_signature_ns.xml') }

        it 'supports implicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default saml ds xs xsi])
        end
      end

      context 'inclusive namespace element is missing' do
        before do
          allow(subject.document).to receive(:at_xpath).
            with('//ec:InclusiveNamespaces', { 'ec' => 'http://www.w3.org/2001/10/xml-exc-c14n#' }).
            and_return(nil)
        end

        it 'return an empty list when inclusive namespace element is missing' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to be_empty
        end
      end
    end
  end
end
