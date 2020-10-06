class SamlIdpController < ApplicationController
  include SamlIdp::Controller

  if Rails::VERSION::MAJOR >= 4
    before_action :add_view_path, only: [:new, :create, :logout]
    before_action :validate_saml_request, only: [:new, :create, :logout]
  else
    before_filter :add_view_path, only: [:new, :create, :logout]
    before_filter :validate_saml_request, only: [:new, :create, :logout]
  end

  def new
    render template: "saml_idp/idp/new"
  end

  def show
    render xml: SamlIdp.metadata.signed
  end

  def create
    unless params[:email].blank? && params[:password].blank?
      person = idp_authenticate(params[:email], params[:password])
      if person.nil?
        @saml_idp_fail_msg = "Incorrect email or password."
      else
        @saml_response = idp_make_saml_response(person)
        render :template => "saml_idp/idp/saml_post", :layout => false
        return
      end
    end
    render :template => "saml_idp/idp/new"
  end

  def logout
    idp_logout
    @saml_response = idp_make_saml_response(nil)
    render :template => "saml_idp/idp/saml_post", :layout => false
  end

  def idp_logout
    raise NotImplementedError
  end
  private :idp_logout

  def idp_authenticate(email, password)
    { :email => email }
  end
  protected :idp_authenticate

  def idp_make_saml_response(person)
    encode_response(person[:email])
  end
  protected :idp_make_saml_response

  private

  def add_view_path
    prepend_view_path("app/views")
  end

end
