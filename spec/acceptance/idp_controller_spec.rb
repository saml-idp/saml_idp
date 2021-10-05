require File.expand_path(File.dirname(__FILE__) + '/acceptance_helper')

feature 'IdpController' do
  before do
    idp_configure("https://foo.example.com/saml/consume")
  end

  scenario 'Login via default signup page' do
    saml_request = make_saml_request("https://foo.example.com/saml/consume")
    visit "/saml/auth?SAMLRequest=#{CGI.escape(saml_request)}"
    expect(status_code).to eq(200)
    # Now we should have the login page for this request
    expect(page).to have_content "Password"
    idp_saml_login
    expect(status_code).to eq(200)
    # Now we should have the assertion that allows us to log in
    click_button 'Submit'   # simulating onload
    expect(current_url).to eq('https://foo.example.com/saml/consume')
    expect(page).to have_content "foo@example.com"
  end

  scenario 'Login with signed request' do
    saml_request = make_saml_request("https://foo.example.com/saml/consume", true)
    visit "/saml/auth?SAMLRequest=#{CGI.escape(saml_request)}"
    idp_saml_login
    click_button 'Submit'   # simulating onload
    expect(page).to have_content "foo@example.com"
  end

  context 'sp requires signature' do
    before do
      idp_configure("https://foo.example.com/saml/consume", true)
    end

    scenario 'Login signed, when signed is needed' do
      saml_request = make_saml_request("https://foo.example.com/saml/consume", true)
      visit "/saml/auth?SAMLRequest=#{CGI.escape(saml_request)}"
      idp_saml_login
      click_button 'Submit'   # simulating onload
      expect(page).to have_content "foo@example.com"
    end

    scenario 'Login unsigned, when signed is needed' do
      saml_request = make_saml_request("https://foo.example.com/saml/consume")
      visit "/saml/auth?SAMLRequest=#{CGI.escape(saml_request)}"
      expect(status_code).to eq(403)
    end

    scenario 'Login with non-embedded signed request' do
      idp_configure("https://foo.example.com/saml/consume", true)
      with_saml_request(embed_sign: false) do |_, _, url|
        visit("/saml/auth?#{URI(url).query.to_s}")
      end
      idp_saml_login
      click_button 'Submit'   # simulating onload
      expect(status_code).to eq(200)
      expect(page).to have_content "foo@example.com"
    end

    scenario 'Login with non-embedded broken signed request' do
      idp_configure("https://foo.example.com/saml/consume", true)
      with_saml_request(embed_sign: false) do |_, _, url|
        visit("/saml/auth?#{URI(url).to_s.gsub('Signature=','Signature=broken')}")
      end
      expect(status_code).to_not eq(200)
    end
  end
end
