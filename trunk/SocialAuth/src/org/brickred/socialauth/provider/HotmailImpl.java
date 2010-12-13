/*
 ===========================================================================
 Copyright (c) 2010 BrickRed Technologies Limited

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sub-license, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 ===========================================================================

 */

package org.brickred.socialauth.provider;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Contact;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.ServerDataException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.brickred.socialauth.util.XMLParseUtil;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.dyuproject.oauth.Endpoint;

/**
 * Implementation of Hotmail provider. This implementation is based on
 * the sample provided by Microsoft. Currently no elements in profile
 * are available and this implements only getContactList() properly
 * 
 * 
 * @author tarunn@brickred.com
 *
 */

public class HotmailImpl extends AbstractProvider implements AuthProvider {

	private WindowsLiveLogin.ConsentToken token;
	private String appid;
	private String secret;
	private final Endpoint __hotmail;
	private WindowsLiveLogin wll;

	public HotmailImpl(final Properties props) {
		__hotmail = Endpoint.load(props, "consent.live.com");
		secret = __hotmail.getConsumerSecret();
		appid = __hotmail.getConsumerKey();
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	public String getLoginRedirectURL(final String redirectUri)
	throws Exception {
		setProviderState(true);
		wll = new WindowsLiveLogin(appid, secret, "wsignin1.0", false,
				redirectUri, redirectUri);
		String consentUrl = wll.getConsentUrl("Contacts.View").toString();
		return consentUrl;
	}

	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * @return Profile object containing the profile information
	 * @param request Request object the request is received from the provider
	 * @throws Exception
	 */

	public Profile verifyResponse(final HttpServletRequest request)
	throws Exception {
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		token = wll.processConsent(request.getParameterMap());
		Profile p = new Profile();
		p.setValidatedId(token.getLocationID());
		return p;
	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * @return List of profile objects representing Contacts. Only name and email
	 * will be available
	 */

	public List<Contact> getContactList() throws Exception {
		HttpClient client = new HttpClient();
		String header = "DelegatedToken dt=\"" + token.getDelegationToken()
		+ "\"";
		String u = "https://livecontacts.services.live.com/users/@L@"
			+ token.getLocationID() + "/LiveContacts/";
		GetMethod get = new GetMethod(u);
		get.addRequestHeader(new Header("Authorization", header));
		List<Contact> plist = new ArrayList<Contact>();
		Element root;
		try {
			client.executeMethod(get);
		} catch (Exception e) {
			throw new SocialAuthException("Error while calling a URL: " + u, e);
		}
		try {
			root = XMLParseUtil.loadXmlResource(get.getResponseBodyAsStream());
		} catch (Exception e) {
			throw new ServerDataException("Unable to retrieve the contacts.", e);
		}
		NodeList contactsList = root.getElementsByTagName("Contacts");
		if (contactsList != null && contactsList.getLength() > 0) {
			for (int i = 0; i < contactsList.getLength(); i++) {
				Element contacts = (Element) contactsList.item(i);
				NodeList contactList = contacts
				.getElementsByTagName("Contact");
				if (contactList != null && contactList.getLength() > 0) {
					for (int j = 0; j < contactList.getLength(); j++) {
						Element contact = (Element) contactList.item(j);
						String fname = XMLParseUtil.getElementData(contact,
						"FirstName");
						String lname = XMLParseUtil.getElementData(contact,
						"LastName");
						String dispName = XMLParseUtil.getElementData(
								contact, "DisplayName");
						String address = XMLParseUtil.getElementData(
								contact, "Address");
						if (address != null && address.length() > 0) {
							Contact p = new Contact();
							p.setFirstName(fname);
							p.setLastName(lname);
							p.setEmail(address);
							p.setDisplayName(dispName);
							plist.add(p);
						}
					}
				}
			}
		}
		return plist;
	}


	public void updateStatus(final String msg) {
		System.out.println("WARNING: not implemented");
	}

	/**
	 * Logout
	 */
	public void logout() {
		token = null;
	}
}
