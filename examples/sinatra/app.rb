require 'securerandom'
require 'sinatra/base'

class App < Sinatra::Base
  register SinatraMore::MarkupPlugin
  include SamlIdp::Controller

  get '/saml-login' do
    erb :login
  end

  post '/saml-login' do
    decode_request(params[:SAMLRequest])

    @saml_response = encode_response(fake_user)

    erb :saml_post
  end

  private

  def fake_user
    OpenStruct.new({
      id: SecureRandom.uuid,
      email_address: params[:email],
    })
  end
end
