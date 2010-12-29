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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.dyuproject.oauth.Constants;
import com.dyuproject.oauth.Consumer;
import com.dyuproject.oauth.Endpoint;
import com.dyuproject.oauth.HttpAuthTransport;
import com.dyuproject.oauth.NonceAndTimestamp;
import com.dyuproject.oauth.Signature;
import com.dyuproject.oauth.SimpleNonceAndTimestamp;
import com.dyuproject.oauth.Token;
import com.dyuproject.oauth.TokenExchange;
import com.dyuproject.oauth.Transport;
import com.dyuproject.util.http.HttpConnector;
import com.dyuproject.util.http.SimpleHttpConnector;
import com.dyuproject.util.http.UrlEncodedParameterMap;
import com.dyuproject.util.http.HttpConnector.Parameter;
import com.dyuproject.util.http.HttpConnector.Response;

/**
 * Provider implementation for Yahoo. This uses the oAuth API
 * provided by Yahoo
 * 
 * @author abhinavm@brickred.com
 * @author tarunn@brickred.com
 *
 */
public class YahooImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = 903564874550419470L;
	private static final String PROFILE_URL = "http://social.yahooapis.com/v1/user/%1$s/profile?format=json";
	private static final String CONTACTS_URL = "http://social.yahooapis.com/v1/user/%1$s/contacts;count=max";
	private static final String UPDATE_STATUS_URL = "http://social.yahooapis.com/v1/user/%1$s/profile/status";

	transient final Log LOG = LogFactory.getLog(YahooImpl.class);
	transient private Consumer __consumer;
	transient private Endpoint __yahoo;
	transient private boolean unserializedFlag;

	private Token token;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;


	public YahooImpl(final Properties props) throws Exception {
		try {
			__yahoo = Endpoint.load(props, "api.login.yahoo.com");
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (__yahoo.getConsumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.login.yahoo.com.consumer_secret value is null");
		}
		if (__yahoo.getConsumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.login.yahoo.com.consumer_key value is null");
		}
		__consumer = Consumer.getInstance();
		unserializedFlag = true;
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
		setProviderState(true);
		token = new Token(__yahoo.getConsumerKey());
		UrlEncodedParameterMap params = new UrlEncodedParameterMap().add(
				Constants.OAUTH_CALLBACK, returnTo);
		Response r;
		try {
			LOG.debug("Call to fetch Request Token");
			r = __consumer.fetchToken(__yahoo, params,
					TokenExchange.REQUEST_TOKEN, token);
		} catch (Exception e) {
			throw e;
		}
		if (r.getStatus() == 200 && token.getState() == Token.UNAUTHORIZED) {
			// unauthorized request token
			StringBuilder urlBuffer = Transport.buildAuthUrl(__yahoo
					.getAuthorizationUrl(), token, returnTo);
			LOG.info("Redirection to following URL should happen : "
					+ urlBuffer.toString());
			return urlBuffer.toString();
		} else {
			LOG.debug("Error while fetching Request Token");
			throw new SocialAuthConfigurationException(
					"Application keys are not correct. "
					+ "The server running the application should be same that was registered to get the keys.");
		}

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
		LOG.info("Verifying the authentication response from provider");
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		if (!unserializedFlag) {
			LOG.debug("Restoring from serialized state");
			restore();
		}

		String verifier = request.getParameter(Constants.OAUTH_VERIFIER);
		if (token.authorize(request.getParameter(Constants.OAUTH_TOKEN),
				verifier)) {
			LOG.debug("Call to fetch Access Token");
			UrlEncodedParameterMap params = new UrlEncodedParameterMap();
			Response r;
			try {
				r = __consumer.fetchToken(__yahoo, params,
						TokenExchange.ACCESS_TOKEN, token);
			} catch (Exception e) {
				throw new SocialAuthException(
				"Error while getting Access Token");
			}
			if (r.getStatus() == 200) {
				isVerify = true;
				return getUserProfile();
			} else {
				throw new SocialAuthException(
						"Unable to retrieve the access token. Status: "
						+ r.getStatus());
			}
		}
		return null;
	}

	private Profile getUserProfile() throws Exception {
		LOG.debug("Obtaining user profile");
		Profile profile = new Profile();
		String url = String.format(PROFILE_URL, token
				.getAttribute("xoauth_yahoo_guid"));
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(url);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __yahoo.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __yahoo,
						token, nts, sig));
		Response serviceResponse = null;
		try {
			serviceResponse = connector.doGET(serviceParams
					.toStringRFC3986(), authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + url);
		}
		if (serviceResponse.getStatus() != 200) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + url
					+ ". Staus :"
					+ serviceResponse.getStatus());
		}
		StringBuffer sb = new StringBuffer();
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					serviceResponse.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			LOG.debug("User Profile :" + sb.toString());
		} catch (Exception exc) {
			throw new SocialAuthException("Failed to read response from  "
					+ url);
		}
		try {
			JSONObject jobj = new JSONObject(sb.toString());
			if (jobj.has("profile")) {
				JSONObject pObj = jobj.getJSONObject("profile");
				if (pObj.has("familyName")) {
					profile.setLastName(pObj.getString("familyName"));
				}
				if (pObj.has("gender")) {
					profile.setGender(pObj.getString("gender"));
				}
				if (pObj.has("givenName")) {
					profile.setFirstName(pObj.getString("givenName"));
				}
				if (pObj.has("location")) {
					profile.setLocation(pObj.getString("location"));
				}
				if (pObj.has("nickname")) {
					profile.setDisplayName(pObj.getString("nickname"));
				}
				if (pObj.has("lang")) {
					profile.setLanguage(pObj.getString("lang"));
				}
				if (pObj.has("birthdate")) {
					profile.setDob(pObj.getString("birthdate"));
				}
				if (pObj.has("image")) {
					JSONObject imgObj = pObj.getJSONObject("image");
					if (imgObj.has("imageUrl")) {
						profile
						.setProfileImageURL(imgObj
								.getString("imageUrl"));
					}
				}
				if (pObj.has("emails")) {
					JSONArray earr = pObj.getJSONArray("emails");
					for (int i = 0; i < earr.length(); i++) {
						JSONObject eobj = earr.getJSONObject(i);
						if (eobj.has("primary")
								&& "true".equals(eobj.getString("primary"))) {
							if (eobj.has("handle")) {
								profile.setEmail(eobj.getString("handle"));
							}
							break;
						}
					}
				}

			}
			return profile;
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the user profile json : " + sb.toString());

		}
	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         email will be available
	 */

	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		String url = String.format(CONTACTS_URL, token
				.getAttribute("xoauth_yahoo_guid"));
		LOG.info("Fetching contacts from " + url);
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(url);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __yahoo.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();
		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __yahoo,
						token, nts, sig));
		List<Contact> plist = new ArrayList<Contact>();
		Response serviceResponse;
		Element root;
		try {
			serviceResponse = connector.doGET(serviceParams
					.toStringRFC3986(), authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the contacts from " + url, ie);
		}
		try {
			root = XMLParseUtil.loadXmlResource(serviceResponse
					.getInputStream());
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the contacts from response." + url, e);
		}
		NodeList contactsList = root.getElementsByTagName("contact");
		if (contactsList != null && contactsList.getLength() > 0) {
			LOG.debug("Found contacts : " + contactsList.getLength());
			for (int i = 0; i < contactsList.getLength(); i++) {
				Element contact = (Element) contactsList.item(i);
				NodeList fieldList = contact.getElementsByTagName("fields");
				if (fieldList != null && fieldList.getLength() > 0) {
					String fname = "";
					String lname = "";
					String dispName = "";
					String address = "";
					List<String> emailArr = new ArrayList<String>();
					for (int j = 0; j < fieldList.getLength(); j++) {
						Element field = (Element) fieldList.item(j);
						String type = XMLParseUtil.getElementData(field,
						"type");

						if ("email".equalsIgnoreCase(type)) {
							if (address.length() > 0) {
								emailArr.add(XMLParseUtil.getElementData(field,
								"value"));
							} else {
								address = XMLParseUtil.getElementData(field,
								"value");
							}
						} else if ("name".equals(type)) {
							fname = XMLParseUtil.getElementData(field,
							"givenName");
							lname = XMLParseUtil.getElementData(field,
							"familyName");
						} else if ("yahooid".equalsIgnoreCase(type)) {
							dispName = XMLParseUtil.getElementData(field,
							"value");
						}
					}
					if (address != null && address.length() > 0) {
						Contact p = new Contact();
						p.setFirstName(fname);
						p.setLastName(lname);
						p.setEmail(address);
						p.setDisplayName(dispName);
						if (emailArr.size() > 0) {
							String arr[] = new String[emailArr.size()];
							int k = 0;
							for (String s : emailArr) {
								arr[k] = s;
								k++;
							}
							p.setOtherEmails(arr);
						}
						plist.add(p);
					}
				}
			}
		} else {
			LOG.debug("No contacts were obtained from : " + CONTACTS_URL);
		}
		return plist;
	}

	/**
	 * Updates the status on the chosen provider if available. This may not be
	 * implemented for all providers.
	 * 
	 * @param msg
	 *            Message to be shown as user's status
	 * @throws Exception
	 */
	public void updateStatus(final String msg) throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		if (msg == null || msg.trim().length() == 0) {
			throw new ServerDataException("Status cannot be blank");
		}
		String url = String.format(UPDATE_STATUS_URL, token
				.getAttribute("xoauth_yahoo_guid"));
		LOG.info("Updating status " + msg + " on " + url);
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(url);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __yahoo.getSignature();
		HttpConnector connector = SimpleHttpConnector.getDefault();
		Parameter authorizationHeader = new Parameter(
				"Authorization",
				getYahooAuthHeaderValue(serviceParams, __yahoo, token, nts, sig));

		Response serviceResponse;
		try {
			String msgBody = "{\"status\":{\"message\":\"" + msg + "\"}}";
			serviceResponse = connector.doPUT(serviceParams.toStringRFC3986(),
					authorizationHeader, null, msgBody
					.getBytes("UTF-8"));
		} catch (IOException ie) {
			throw new SocialAuthException("Failed to update status on " + url,
					ie);
		}
		LOG.debug("Status Updated and return status code is : "
				+ serviceResponse.getStatus());
		// return 204

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
			__yahoo = Endpoint.load(this.properties, "api.login.yahoo.com");
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		__consumer = Consumer.getInstance();
	}

	private String getYahooAuthHeaderValue(final UrlEncodedParameterMap params,
			final Endpoint ep, final Token token, final NonceAndTimestamp nts,
			final Signature signature) {
		StringBuilder oauthBuffer = new StringBuilder();
		params.put(Constants.OAUTH_CONSUMER_KEY, ep.getConsumerKey());
		params.put(Constants.OAUTH_TOKEN, token.getKey());
		nts.put(params, ep.getConsumerKey());
		Signature.Listener __authHeaderListener = new Signature.Listener() {
			public void handleOAuthParameter(final String key,
					final String value, final StringBuilder oauthBuffer) {
				oauthBuffer.append(',').append(key).append('=').append('"')
				.append(value).append('"');
			}

			public void handleRequestParameter(final String key,
					final String value, final StringBuilder requestBuffer) {

			}
		};
		signature.generate(params, ep.getConsumerSecret(), token,
				HttpConnector.PUT, __authHeaderListener, oauthBuffer, null);

		oauthBuffer.setCharAt(0, ' ');
		oauthBuffer.insert(0, "OAuth");

		return oauthBuffer.toString();
	}



}
