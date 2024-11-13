require File.expand_path("#{File.dirname(__FILE__)}/acceptance_helper")

feature 'IdpController' do
  scenario 'Login via default signup page' do
    saml_request = custom_saml_request(
      overrides: {
        assertion_consumer_service_url: 'http://foo.example.com/saml/consume',
      }
    )
    visit "/saml/auth?SAMLRequest=#{CGI.escape(saml_request)}"
    fill_in 'Email', with: 'foo@example.com'
    fill_in 'Password', with: 'okidoki'
    click_on 'Sign in'
    click_on 'Submit' # simulating onload

    expect(current_url).to eq('http://foo.example.com/saml/consume')
    expect(page).to have_content 'foo@example.com'
  end
end
