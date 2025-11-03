require 'spec_helper'

module SamlIdp
  describe SignedInfoBuilder do
    let(:reference_id) { "abc" }
    let(:digest) { "em8csGAWynywpe8S4nN64o56/4DosXi2XWMY6RJ6YfA=" }
    let(:algorithm) { :sha256 }
    subject { described_class.new(
      reference_id,
      digest,
      algorithm,
      sp_encrypted_pv_key[:sp_encrypted_pv_key],
      sp_encrypted_pv_key[:pv_key_password]
    ) }

    before do
      allow(Time).to receive(:now).and_return Time.parse("Jul 31 2013")
    end

    it "builds a legit raw XML file" do
      expect(subject.raw).to eq("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#_abc\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>em8csGAWynywpe8S4nN64o56/4DosXi2XWMY6RJ6YfA=</ds:DigestValue></ds:Reference></ds:SignedInfo>")
    end

    it "builds a legit digest of the XML file" do
      expect(subject.signed).to eq("YP2e6cTEfRj1vI1/gaaSApLAMxPBQzyuBvbvulbS99x17LCLDSKvqA6MyU4WLavmVba5qiF88e97f0XKLsse7gEGOfnF/6jaRV3fePXk6+LFaeYUHZ11u7PkZ1/ucO459ASsuPN/9P9xCY2t+jtVKvIrcSZQbomymfsWGt9P/oY83elKU712aAwqcfvINsa1N+RefZRwdAW4ATBwwcDjE3VTR6mKOyGMsPJ4HQcPrNiEmuwd1QaPH0H1LLzxtewGQGmIL2UqNE/QMe/kKiSTFZ0loBKuSEc9WBw5XuH31QxbzpLJjqM/C1qy4aykPqDUuJtQ4csx78GgfFS4uiqowg==")
    end
  end
end
