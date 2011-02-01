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
 * Implementation of Hotmail provider. This implementation is based on
 * the sample provided by Microsoft. Currently no elements in profile
 * are available and this implements only getContactList() properly
 * 
 * 
 * @author tarunn@brickred.com
 *
 */

public class LinkedInImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = -6141448721085510813L;
	private static final String CONNECTION_URL = "http://api.linkedin.com/v1/people/~/connections:(id,first-name,last-name,public-profile-url)";
	private static final String UPDATE_STATUS_URL = "http://api.linkedin.com/v1/people/~/shares";
	private static final String PROFILE_URL = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,languages,date-of-birth,picture-url,location:(name))";
	private static final String STATUS_BODY = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><share><comment>%1$s</comment><visibility><code>anyone</code></visibility></share>";
	private static final String PROPERTY_DOMAIN = "api.linkedin.com";
	private final Log LOG = LogFactory.getLog(LinkedInImpl.class);

	transient private Consumer __consumer;
	transient private Endpoint __linkedin;
	transient private boolean unserializedFlag;

	private Token token;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;


	public LinkedInImpl(final Properties props)
	throws Exception {
		try {
			__linkedin = Endpoint.load(props, PROPERTY_DOMAIN);
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (__linkedin.getConsumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.linkedin.com.consumer_secret value is null");
		}
		if (__linkedin.getConsumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.linkedin.com.consumer_key value is null");
		}
		__consumer = Consumer.newInstance(this.properties);
		unserializedFlag = true;
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	public String getLoginRedirectURL(final String returnTo)
	throws Exception {
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		token = new Token(__linkedin.getConsumerKey());
		UrlEncodedParameterMap params = new UrlEncodedParameterMap().add(
				Constants.OAUTH_CALLBACK, returnTo);
		Response r;
		try {
			LOG.debug("Call to fetch Request Token");
			r = __consumer.fetchToken(__linkedin, params,
					TokenExchange.REQUEST_TOKEN, token);
		} catch (Exception e) {
			throw e;
		}
		if (r.getStatus() == 200 && token.getState() == Token.UNAUTHORIZED) {
			StringBuilder urlBuffer = Transport.buildAuthUrl(__linkedin
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
				r = __consumer.fetchToken(__linkedin, params,
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

	/**
	 * Gets the list of contacts of the user and their email.
	 * @return List of profile objects representing Contacts. Only name and email
	 * will be available
	 */

	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		LOG.info("Fetching contacts from " + CONNECTION_URL);
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				CONNECTION_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __linkedin.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();
		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __linkedin,
						token, nts, sig));
		Response serviceResponse;
		try {
			serviceResponse = connector.doGET(serviceParams.toStringRFC3986(),
					authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the connections from " + CONNECTION_URL,
					ie);
		}
		Element root;
		try {
			root = XMLParseUtil.loadXmlResource(serviceResponse
					.getInputStream());
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the profile from response."
					+ CONNECTION_URL, e);
		}
		List<Contact> contactList = new ArrayList<Contact>();
		if (root != null) {
			NodeList pList = root.getElementsByTagName("person");
			if (pList != null && pList.getLength() > 0) {
				LOG.debug("Found contacts : " + pList.getLength());
				for (int i = 0; i < pList.getLength(); i++) {
					Element p = (Element) pList.item(i);
					String fname = XMLParseUtil.getElementData(p, "first-name");
					String lname = XMLParseUtil.getElementData(p, "last-name");
					String id = XMLParseUtil.getElementData(p, "id");
					String profileUrl = XMLParseUtil.getElementData(p,
					"public-profile-url");
					if (id != null) {
						Contact cont = new Contact();
						if (fname != null) {
							cont.setFirstName(fname);
						}
						if (lname != null) {
							cont.setLastName(lname);
						}
						if (profileUrl != null) {
							cont.setProfileUrl(profileUrl);
						}
						contactList.add(cont);
					}
				}
			} else {
				LOG.debug("No connections were obtained from : "
						+ CONNECTION_URL);
			}
		}
		return contactList;
	}


	public void updateStatus(final String msg) throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		if (msg == null || msg.trim().length() == 0) {
			throw new ServerDataException("Status cannot be blank");
		}
		if (msg.length() > 700) {
			throw new ServerDataException(
			"Status cannot be more than 700 characters.");
		}
		LOG.info("Updating status " + msg + " on " + UPDATE_STATUS_URL);
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				UPDATE_STATUS_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __linkedin.getSignature();
		HttpConnector connector = SimpleHttpConnector.getDefault();
		Parameter authorizationHeader = new Parameter("Authorization",
				getLinkedInAuthHeaderValue(serviceParams, __linkedin, token,
						nts,
						sig));

		Response serviceResponse;
		try {
			String msgBody = String.format(STATUS_BODY, msg);
			serviceResponse = connector.doPOST(serviceParams.toStringRFC3986(),
					authorizationHeader, "text/xml", msgBody.getBytes("UTF-8"));
		} catch (IOException ie) {
			throw new SocialAuthException("Failed to update status on "
					+ UPDATE_STATUS_URL,
					ie);
		}
		LOG.debug("Status Updated and return status code is : "
				+ serviceResponse.getStatus());
		// return 201
	}

	/**
	 * Logout
	 */
	public void logout() {
		token = null;
	}

	private Profile getUserProfile() throws Exception {
		LOG.debug("Obtaining user profile");
		Profile profile = new Profile();
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				PROFILE_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __linkedin.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __linkedin,
						token, nts, sig));
		Response serviceResponse = null;
		try {
			serviceResponse = connector.doGET(serviceParams.toStringRFC3986(),
					authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + PROFILE_URL);
		}
		if (serviceResponse.getStatus() != 200) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + PROFILE_URL
					+ ". Staus :" + serviceResponse.getStatus());
		}
		Element root;
		try {
			root = XMLParseUtil.loadXmlResource(serviceResponse
					.getInputStream());
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the profile from response." + PROFILE_URL,
					e);
		}

		if (root != null) {
			String fname = XMLParseUtil.getElementData(root, "first-name");
			String lname = XMLParseUtil.getElementData(root, "last-name");
			NodeList dob = root.getElementsByTagName("date-of-birth");
			if (dob != null && dob.getLength() > 0) {
				Element dobel = (Element) dob.item(0);
				if (dobel != null) {
					String y = XMLParseUtil.getElementData(dobel, "year");
					String m = XMLParseUtil.getElementData(dobel, "month");
					String d = XMLParseUtil.getElementData(dobel, "day");
					if (m == null) {
						m = "";
					}
					if (d != null) {
						m += "-" + d;
					}
					if (y != null) {
						m += "-" + y;
					}
					if (m.length() > 0) {
						profile.setDob(m);
					}
				}
			}
			String picUrl = XMLParseUtil.getElementData(root, "picture-url");
			String id = XMLParseUtil.getElementData(root, "id");
			if (picUrl != null) {
				profile.setProfileImageURL(picUrl);
			}
			NodeList location = root.getElementsByTagName("location");
			if (location != null && location.getLength() > 0) {
				Element locationEl = (Element) location.item(0);
				String loc = XMLParseUtil.getElementData(locationEl, "name");
				if (loc != null) {
					profile.setLocation(loc);
				}
			}
			profile.setFirstName(fname);
			profile.setLastName(lname);
			profile.setValidatedId(id);
			LOG.debug("User Profile :" + profile.toString());
		}
		return profile;
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

	private String getLinkedInAuthHeaderValue(
			final UrlEncodedParameterMap params, final Endpoint ep,
			final Token token, final NonceAndTimestamp nts,
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
				HttpConnector.POST, __authHeaderListener, oauthBuffer, null);

		oauthBuffer.setCharAt(0, ' ');
		oauthBuffer.insert(0, "OAuth");

		return oauthBuffer.toString();
	}

	private void restore() throws Exception {
		try {
			__linkedin = Endpoint.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		__consumer = Consumer.newInstance(this.properties);
	}
}
