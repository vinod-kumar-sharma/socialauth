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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Contact;
import org.brickred.socialauth.Permission;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.ServerDataException;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.brickred.socialauth.exception.UserDeniedPermissionException;
import org.brickred.socialauth.util.HttpUtil;
import org.brickred.socialauth.util.MethodType;
import org.brickred.socialauth.util.OAuthConfig;
import org.brickred.socialauth.util.OAuthConsumer;
import org.brickred.socialauth.util.OpenIdConsumer;
import org.brickred.socialauth.util.Response;
import org.brickred.socialauth.util.Token;
import org.brickred.socialauth.util.XMLParseUtil;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Provider implementation for Google
 * 
 * @author abhinavm@brickred.com
 * 
 */
public class GoogleImpl extends AbstractProvider implements AuthProvider,
		Serializable {
	private static final long serialVersionUID = -6075582192266022341L;
	private static final String REQUEST_TOKEN_URL = "https://www.google.com/accounts/o8/ud";
	private static final String ACCESS_TOKEN_URL = "https://www.google.com/accounts/OAuthGetAccessToken";
	private static final String OAUTH_SCOPE = "http://www.google.com/m8/feeds/";
	private static final String CONTACTS_FEED_URL = "http://www.google.com/m8/feeds/contacts/default/full/?max-results=1000";
	private static final String CONTACT_NAMESPACE = "http://schemas.google.com/g/2005";
	private static final String PROPERTY_DOMAIN = "www.google.com";

	private final Log LOG = LogFactory.getLog(GoogleImpl.class);

	private Permission scope;
	private Properties properties;
	private boolean isVerify;
	private Token requestToken;
	private Token accessToken;
	private OAuthConsumer oauth;
	private OAuthConfig config;

	public GoogleImpl(final Properties props) throws Exception {

		try {
			this.properties = props;
			config = OAuthConfig.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (config.get_consumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
					"www.google.com.consumer_secret value is null");
		}
		if (config.get_consumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
					"www.google.com.consumer_key value is null");
		}
		oauth = new OAuthConsumer(config);
		requestToken = null;
		accessToken = null;
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */
	@Override
	public String getLoginRedirectURL(final String returnTo) throws Exception {
		LOG.info("Determining URL for redirection");
		String associationURL = OpenIdConsumer
				.getAssociationURL(REQUEST_TOKEN_URL);
		Response r = HttpUtil.doHttpRequest(associationURL,
				MethodType.GET.toString(), null, null);
		StringBuffer sb = new StringBuffer();
		String assocHandle = "";
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					r.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
				if (line.substring(0, 13) == "assoc_handle:") {
					assocHandle = line.substring(13);
					break;
				}
			}
			LOG.debug("ASSOCCIATION : " + assocHandle);
		} catch (Exception exc) {
			throw new SocialAuthException("Failed to read response from  ");
		}

		String realm = returnTo.substring(0, returnTo.indexOf("/", 9));
		String consumerURL = realm.replace("http://", "");

		setProviderState(true);
		String gscope = null;
		if (!Permission.AUHTHENTICATE_ONLY.equals(this.scope)) {
			gscope = OAUTH_SCOPE;
		}
		String url = OpenIdConsumer.getRequestTokenURL(REQUEST_TOKEN_URL,
				returnTo, realm, assocHandle, consumerURL, gscope);
		LOG.info("Redirection to following URL should happen : " + url);
		return url;

	}

	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * @return Profile object containing the profile information
	 * @param request
	 *            Request object the request is received from the provider
	 * @throws Exception
	 */
	@Override
	public Profile verifyResponse(final HttpServletRequest request)
			throws Exception {
		LOG.info("Verifying the authentication response from provider");
		LOG.debug("Verifying the authentication response from provider");
		if (request.getParameter("openid.mode") != null
				&& "cancel".equals(request.getParameter("openid.mode"))) {
			throw new UserDeniedPermissionException();
		}
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		try {
			LOG.debug("Running OpenID discovery");
			String reqTokenStr = "";
			if (Permission.AUHTHENTICATE_ONLY.equals(this.scope)) {
				return getProfile(request);
			} else {
				if (request.getParameter(OpenIdConsumer.OPENID_REQUEST_TOKEN) != null) {
					reqTokenStr = HttpUtil.decodeURIComponent(request
							.getParameter(OpenIdConsumer.OPENID_REQUEST_TOKEN));
				}
				requestToken = new Token();
				requestToken.setKey(reqTokenStr);
				LOG.debug("Call to fetch Access Token");
				accessToken = oauth.getAccessToken(ACCESS_TOKEN_URL,
						requestToken);
				isVerify = true;
				LOG.debug("Obtaining profile from OpenID response");
				return getProfile(request);
			}
		} catch (Exception e) {
			throw new SocialAuthException(e);
		}
	}

	private Profile getProfile(final HttpServletRequest req) {
		return OpenIdConsumer.getUserInfo(req);
	}

	@Override
	public void updateStatus(final String msg) throws Exception {
		LOG.warn("WARNING: Not implemented for Google");
		throw new SocialAuthException(
				"Update Status is not implemented for Gmail");
	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         email will be available
	 * 
	 * @throws Exception
	 */
	@Override
	public List<Contact> getContactList() throws Exception {
		LOG.info("Fetching contacts from " + CONTACTS_FEED_URL);
		if (!isVerify) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		if (accessToken == null) {
			throw new SocialAuthConfigurationException(
					"Application keys are not correct. "
							+ "The server running the application should be same that was registered to get the keys.");
		}

		Map<String, String> params = new HashMap<String, String>();
		Response serviceResponse = null;
		try {
			serviceResponse = oauth.httpGet(CONTACTS_FEED_URL, null,
					accessToken);
		} catch (Exception ie) {
			throw new SocialAuthException(
					"Failed to retrieve the contacts from " + CONTACTS_FEED_URL,
					ie);
		}
		List<Contact> plist = new ArrayList<Contact>();
		Element root;

		try {
			root = XMLParseUtil.loadXmlResource(serviceResponse
					.getInputStream());
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the contacts from response."
							+ CONTACTS_FEED_URL, e);
		}
		NodeList contactsList = root.getElementsByTagName("entry");
		if (contactsList != null && contactsList.getLength() > 0) {
			LOG.debug("Found contacts : " + contactsList.getLength());
			for (int i = 0; i < contactsList.getLength(); i++) {
				Element contact = (Element) contactsList.item(i);
				String fname = "";
				NodeList l = contact.getElementsByTagNameNS(CONTACT_NAMESPACE,
						"email");
				String address = null;
				String emailArr[] = null;
				if (l != null && l.getLength() > 0) {
					Element el = (Element) l.item(0);
					if (el != null) {
						address = el.getAttribute("address");
					}
					if (l.getLength() > 1) {
						emailArr = new String[l.getLength() - 1];
						for (int k = 1; k < l.getLength(); k++) {
							Element e = (Element) l.item(k);
							if (e != null) {
								emailArr[k - 1] = e.getAttribute("address");
							}
						}
					}
				}
				String lname = "";
				String dispName = XMLParseUtil.getElementData(contact, "title");
				if (dispName != null) {
					String sarr[] = dispName.split(" ");
					if (sarr.length > 0) {
						if (sarr.length >= 1) {
							fname = sarr[0];
						}
						if (sarr.length >= 2) {
							StringBuilder sb = new StringBuilder();
							for (int k = 1; k < sarr.length; k++) {
								sb.append(sarr[k]).append(" ");
							}
							lname = sb.toString();
						}
					}
				}
				if (address != null && address.length() > 0) {
					Contact p = new Contact();
					p.setFirstName(fname);
					p.setLastName(lname);
					p.setEmail(address);
					p.setDisplayName(dispName);
					p.setOtherEmails(emailArr);
					plist.add(p);
				}
			}
		} else {
			LOG.debug("No contacts were obtained from the feed : "
					+ CONTACTS_FEED_URL);
		}
		return plist;
	}

	/**
	 * Logout
	 */
	@Override
	public void logout() {
		requestToken = null;
		accessToken = null;
	}

	/**
	 * 
	 * @param p
	 *            Permission object which can be Permission.AUHTHENTICATE_ONLY,
	 *            Permission.ALL, Permission.DEFAULT
	 */
	@Override
	public void setPermission(final Permission p) {
		LOG.debug("Permission requested : " + p.toString());
		this.scope = p;
	}

}
