# frozen_string_literal: true

require 'spec_helper'

describe 'POST /saml-login ' do
  it 'encodes a SAMLResponse' do
    allow_any_instance_of(SamlIdp::Controller).to receive(:decode_request).and_return(true)
    allow_any_instance_of(SamlIdp::Controller).to receive(:encode_response).and_return("SAMLResponse")

    post("/saml-login")

    expect(last_response).to be_ok
  end
end
