class SamlController < ApplicationController

  def consume
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    if Gem::Requirement.new('< 4.1') =~ Gem::Version.new(Rails.version)
      render :text => response.name_id
    else
      render :plain => response.name_id
    end
  end

end
