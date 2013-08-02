require 'spec_helper'
module SamlIdp
  describe AssertionBuilder do
    let(:reference_id) { "abc" }
    let(:issuer_uri) { "http://sportngin.com" }
    let(:name_id) { "jon.phenow@sportngin.com" }
    let(:audience_uri) { "http://example.com" }
    let(:saml_request_id) { "123" }
    let(:saml_acs_url) { "http://saml.acs.url" }
    let(:algorithm) { :sha256 }
    subject { described_class.new(
      reference_id,
      issuer_uri,
      name_id,
      audience_uri,
      saml_request_id,
      saml_acs_url,
      algorithm
    ) }

    before do
      Time.stub now: Time.parse("Jul 31 2013")
    end

    it "builds a legit raw XML file" do
      subject.raw.should == "<Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_abc\" IssueInstant=\"2013-07-31T05:00:00Z\" Version=\"2.0\"><Issuer>http://sportngin.com</Issuer><Subject><NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">jon.phenow@sportngin.com</NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><SubjectConfirmationData InResponseTo=\"123\" NotOnOrAfter=\"2013-07-31T05:03:00Z\" Recipient=\"http://saml.acs.url\"/></SubjectConfirmation></Subject><Conditions NotBefore=\"2013-07-31T04:59:55Z\" NotOnOrAfter=\"2013-07-31T06:00:00Z\"><AudienceRestriction><Audience>http://example.com</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><AttributeValue>jon.phenow@sportngin.com</AttributeValue></Attribute></AttributeStatement><AuthnStatment AuthnInstant=\"2013-07-31T05:00:00Z\" SessionIndex=\"_abc\"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatment></Assertion>"
    end

    it "builds a legit digest of the XML file" do
      subject.digest.should == "B4RychQTGtb6QPDwBrIYiz2Hq3SjEP1HaKmwFZSpA5o="
    end

    it "rebuilds with signature" do
      subject.signature = "<signature>stuff</signature>"
      subject.rebuild.should == "<Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_abc\" IssueInstant=\"2013-07-31T05:00:00Z\" Version=\"2.0\"><Issuer>http://sportngin.com</Issuer><signature>stuff</signature><Subject><NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">jon.phenow@sportngin.com</NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><SubjectConfirmationData InResponseTo=\"123\" NotOnOrAfter=\"2013-07-31T05:03:00Z\" Recipient=\"http://saml.acs.url\"/></SubjectConfirmation></Subject><Conditions NotBefore=\"2013-07-31T04:59:55Z\" NotOnOrAfter=\"2013-07-31T06:00:00Z\"><AudienceRestriction><Audience>http://example.com</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><AttributeValue>jon.phenow@sportngin.com</AttributeValue></Attribute></AttributeStatement><AuthnStatment AuthnInstant=\"2013-07-31T05:00:00Z\" SessionIndex=\"_abc\"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatment></Assertion>"
    end
  end
end