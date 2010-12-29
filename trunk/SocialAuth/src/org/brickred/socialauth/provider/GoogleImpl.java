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

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
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
import org.brickred.socialauth.util.XMLParseUtil;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.dyuproject.oauth.Endpoint;
import com.dyuproject.oauth.HttpAuthTransport;
import com.dyuproject.oauth.NonceAndTimestamp;
import com.dyuproject.oauth.Signature;
import com.dyuproject.oauth.SimpleNonceAndTimestamp;
import com.dyuproject.oauth.Token;
import com.dyuproject.oauth.TokenExchange;
import com.dyuproject.oauth.Transport;
import com.dyuproject.openid.OpenIdUser;
import com.dyuproject.openid.RelyingParty;
import com.dyuproject.openid.YadisDiscovery;
import com.dyuproject.openid.RelyingParty.ListenerCollection;
import com.dyuproject.openid.ext.AxSchemaExtension;
import com.dyuproject.openid.ext.SRegExtension;
import com.dyuproject.util.http.HttpConnector;
import com.dyuproject.util.http.SimpleHttpConnector;
import com.dyuproject.util.http.UrlEncodedParameterMap;
import com.dyuproject.util.http.HttpConnector.Parameter;
import com.dyuproject.util.http.HttpConnector.Response;

/**
 * Provider implementation for Google
 * 
 * @author abhinavm@brickred.com
 * 
 */
public class GoogleImpl extends AbstractProvider implements AuthProvider,
Serializable
{
	private static final long serialVersionUID = -6075582192266022341L;
	private static final String GOOGLE_IDENTIFIER = "https://www.google.com/accounts/o8/id";
	private static final String GOOGLE_OPENID_SERVER = "https://www.google.com/accounts/o8/ud";
	private static final String OAUTH_SCOPE = "http://www.google.com/m8/feeds/";
	private static final String CONTACTS_FEED_URL = "http://www.google.com/m8/feeds/contacts/default/full/?max-results=1000";

	transient final Log LOG = LogFactory.getLog(GoogleImpl.class);
	transient private Endpoint __google;
	transient private ListenerCollection listeners;
	transient private boolean unserializedFlag;

	private OpenIdUser user;
	private Token token;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;

	public GoogleImpl(final Properties props) throws Exception {

		try {
			__google = Endpoint.load(props, "www.google.com");
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (__google.getConsumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
			"www.google.com.consumer_secret value is null");
		}
		if (__google.getConsumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
			"www.google.com.consumer_key value is null");
		}
		unserializedFlag = true;
		addListenerCollection();
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */
	public String getLoginRedirectURL(final String returnTo) throws Exception {

		LOG.info("Determining URL for redirection");
		RelyingParty _relyingParty = RelyingParty.getInstance();
		// we expect it to be google so skip discovery to speed up the
		// openid process

		LOG
		.debug("Preparing listeneres for OpenID authentication using dyuproject.");
		user = OpenIdUser.populate(GOOGLE_IDENTIFIER,
				YadisDiscovery.IDENTIFIER_SELECT, GOOGLE_OPENID_SERVER);
		user.setAttribute("google_scope", OAUTH_SCOPE);
		user.setAttribute("google_type", "contacts");

		// associate and authenticate user
		StringBuffer url = new StringBuffer(returnTo);
		String trustRoot = url.substring(0, url.indexOf("/", 9));
		String realm = url.substring(0, url.lastIndexOf("/"));

		_relyingParty.getOpenIdContext().getAssociation().associate(user,
				_relyingParty.getOpenIdContext());
		UrlEncodedParameterMap params = RelyingParty.getAuthUrlMap(user,
				trustRoot,
				realm, returnTo);
		listeners.onPreAuthenticate(user, null, params);
		setProviderState(true);
		LOG.info("Redirection to following URL should happen : "
				+ params.toStringRFC3986());
		return params.toStringRFC3986();

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
	public Profile verifyResponse(final HttpServletRequest request)
	throws Exception {
		LOG.info("Verifying the authentication response from provider");
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		if (!unserializedFlag) {
			LOG.debug("Restoring from serialized state");
			restore();
		}
		try {
			LOG.debug("Running OpenID discovery");
			RelyingParty _relyingParty = RelyingParty.getInstance();
			request.setAttribute(OpenIdUser.ATTR_NAME, user);
			user = _relyingParty.discover(request);

			if (user.isAssociated() && RelyingParty.isAuthResponse(request)) {
				LOG.debug("Verifying OpenID authentication");
				// verify authentication

				if (_relyingParty.getOpenIdContext().getAssociation()
						.verifyAuth(user,
								RelyingParty.getAuthParameters(request),
								_relyingParty.getOpenIdContext()))
				{
					listeners.onAuthenticate(this.user, request);

					Map<String, String> sreg = SRegExtension.remove(user);
					Map<String, String> axschema = AxSchemaExtension
					.remove(user);
					if (sreg != null && !sreg.isEmpty()) {
						LOG.debug("sreg: " + sreg);
						user.setAttribute("info", sreg);
					} else if (axschema != null && !axschema.isEmpty()) {
						LOG.debug("axschema: " + axschema);
						user.setAttribute("info", axschema);
					}
					String alias = user.getExtension(EXT_NAMESPACE);
					if (alias != null) {
						String requestToken = request
						.getParameter("openid." + alias
								+ ".request_token");
						LOG.debug("Obtained request token :" + requestToken);
						token = new Token(__google.getConsumerKey(),
								requestToken, null, Token.AUTHORIZED);
						UrlEncodedParameterMap accessTokenParams = new UrlEncodedParameterMap();
						try {
							Response accessTokenResponse = fetchToken(
									TokenExchange.ACCESS_TOKEN,
									accessTokenParams, __google, token);
							if (accessTokenResponse.getStatus() == 200
									&& token.getState() == Token.ACCESS_TOKEN) {
								user
								.setAttribute("token_k", token
										.getKey());
								user.setAttribute("token_s", token
										.getSecret());
								isVerify = true;

							} else {
								throw new SocialAuthException(
										"Unable to retrieve the access token. Status: "
										+ accessTokenResponse
										.getStatus());
							}
						} catch (IOException e) {
							throw new SocialAuthException(
									"Unable to retrieve the access token", e);
						}
					}

					LOG.debug("Obtaining profile from OpenID response");
					Profile p = new Profile();
					if (user.getAttribute("info") != null) {
						Map<String, String> info = (Map<String, String>) user
						.getAttribute("info");

						p.setEmail(info.get(EMAIL));
						p.setFirstName(info.get(FIRST_NAME));
						p.setLastName(info.get(LAST_NAME));
						p.setCountry(info.get(COUNTRY));
						p.setLanguage(info.get(LANGUAGE));
						p.setFullName(info.get(FULL_NAME));
						p.setDisplayName(info.get(NICK_NAME));
						p.setLocation(info.get(POSTCODE));
						p.setDob(info.get(DOB));
						p.setGender(info.get(GENDER));
						p.setValidatedId(user.getIdentifier());
					}
					return p;
				}
			}
		} catch (Exception e) {
			throw new SocialAuthException(e);
		}
		return null;
	}

	public void updateStatus(final String msg) {
		LOG.warn("WARNING: Not implemented for Google");
	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         email will be available
	 * 
	 * @throws Exception
	 */
	public List<Contact> getContactList() throws Exception {
		LOG.info("Fetching contacts from " + CONTACTS_FEED_URL);
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		if (token == null) {
			throw new SocialAuthConfigurationException(
					"Application keys are not correct. "
					+ "The server running the application should be same that was registered to get the keys.");
		}
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				CONTACTS_FEED_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __google.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __google,
						token, nts, sig));

		List<Contact> plist = new ArrayList<Contact>();
		Response serviceResponse;
		Element root;
		try {
			serviceResponse = connector.doGET(serviceParams
					.toStringRFC3986(), authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the contacts from " + CONTACTS_FEED_URL,
					ie);
		}

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
				NodeList l = contact.getElementsByTagNameNS(
						"http://schemas.google.com/g/2005", "email");
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
				String dispName = XMLParseUtil.getElementData(contact,
				"title");
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

	private Response fetchToken(final TokenExchange exchange,
			final UrlEncodedParameterMap params, final Endpoint endpoint,
			final Token token) throws IOException {
		// via GET, POST or Authorization
		Transport transport = endpoint.getTransport();

		// via HMAC-SHA1 or PLAINTEXT
		Signature sig = endpoint.getSignature();

		// nonce and timestamp generator
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();

		// http connector
		HttpConnector connector = SimpleHttpConnector.getDefault();

		// returns the http response
		return transport.send(params, endpoint, token, exchange, nts, sig,
				connector);
	}

	/**
	 * Logout
	 */
	public void logout() {
		token = null;
	}

	/**
	 * 
	 * @param p
	 *            Permission object which can be Permission.AUHTHENTICATE_ONLY,
	 *            Permission.ALL, Permission.DEFAULT
	 */
	public void setPermission(final Permission p) {
		LOG.debug("Permission requested : " + p.toString());
		this.scope = p;
	}

	private void restore() throws Exception {
		try {
			__google = Endpoint.load(this.properties, "www.google.com");
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		addListenerCollection();
	}

	private void addListenerCollection() throws Exception {
		listeners = new ListenerCollection();
		listeners.addListener(new SRegExtension().addExchange(EMAIL)
				.addExchange(COUNTRY).addExchange(LANGUAGE).addExchange(
						FULL_NAME).addExchange(NICK_NAME).addExchange(DOB)
						.addExchange(GENDER).addExchange(POSTCODE));
		listeners.addListener(new AxSchemaExtension().addExchange(EMAIL)
				.addExchange(FIRST_NAME).addExchange(LAST_NAME).addExchange(
						COUNTRY).addExchange(LANGUAGE).addExchange(FULL_NAME)
						.addExchange(NICK_NAME).addExchange(DOB).addExchange(GENDER)
						.addExchange(POSTCODE));
		listeners.addListener(new RelyingParty.Listener() {
			public void onDiscovery(final OpenIdUser user,
					final HttpServletRequest request) {
				LOG.debug("discovered user: " + user.getClaimedId());
			}

			public void onPreAuthenticate(final OpenIdUser user,
					final HttpServletRequest request,
					final UrlEncodedParameterMap params) {

				params.add("openid.ns.oauth", EXT_NAMESPACE);
				params.put("openid.oauth.consumer", __google.getConsumerKey());
				params.put("openid.oauth.scope", OAUTH_SCOPE);

				LOG.debug("pre-authenticate user: "
						+ user.getClaimedId());

			}

			public void onAuthenticate(final OpenIdUser user,
					final HttpServletRequest request) {

			}

			public void onAccess(final OpenIdUser user,
					final HttpServletRequest request) {
				LOG.debug("user access: " + user.getIdentity());
				LOG.debug("info: " + user.getAttribute("info"));
			}
		});
	}
}
