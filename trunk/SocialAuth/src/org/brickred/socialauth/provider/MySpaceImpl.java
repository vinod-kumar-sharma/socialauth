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
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

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
import org.brickred.socialauth.util.OAuthConsumer;
import org.json.JSONArray;
import org.json.JSONObject;

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
 * Provider implementation for Myspace
 * 
 */
public class MySpaceImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = -4074039782095430942L;
	private static final String PROPERTY_DOMAIN = "api.myspace.com";
	private static final String PROFILE_URL = "http://api.myspace.com/1.0/people/@me/@self";
	private static final String CONTACTS_URL = "http://api.myspace.com/1.0/people/@me/@all";
	private static final String UPDATE_STATUS_URL = "http://api.myspace.com/1.0/statusmood/@me/@self";
	private final Log LOG = LogFactory.getLog(MySpaceImpl.class);

	transient private Consumer __consumer;
	transient private Endpoint __myspace;
	transient private boolean unserializedFlag;

	private Token token;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;

	public MySpaceImpl(final Properties props) throws Exception {
		try {
			__myspace = Endpoint.load(props, PROPERTY_DOMAIN);
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (__myspace.getConsumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.myspace.com.consumer_secret value is null");
		}
		if (__myspace.getConsumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
			"api.myspace.com.consumer_key value is null");
		}
		__consumer = Consumer.newInstance(props);
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
		token = new Token(__myspace.getConsumerKey());
		UrlEncodedParameterMap params = new UrlEncodedParameterMap().add(
				Constants.OAUTH_CALLBACK, returnTo);

		Response r;
		try {
			LOG.debug("Call to fetch Request Token");
			r = __consumer.fetchToken(__myspace, params,
					TokenExchange.REQUEST_TOKEN, token);
		} catch (Exception e) {
			throw e;
		}
		if (r.getStatus() == 200 && token.getState() == Token.UNAUTHORIZED) {
			// unauthorized request token
			StringBuilder urlBuffer = Transport
			.buildAuthUrl(
					__myspace.getAuthorizationUrl()
					+ "?myspaceid.permissions=VIEWER_FULL_PROFILE_INFO|ViewFullProfileInfo|UpdateMoodStatus",
					token, returnTo);
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

		String verifier = request.getParameter(Constants.OAUTH_VERIFIER);
		if (token.authorize(URLDecoder.decode(request
				.getParameter(Constants.OAUTH_TOKEN), "UTF-8"),
				verifier)) {
			LOG.debug("Call to fetch Access Token");
			UrlEncodedParameterMap params = new UrlEncodedParameterMap();
			Response r;
			try {
				r = __consumer.fetchToken(__myspace, params,
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
	 * Gets the list of contacts of the user and their profile URL.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         profile URL will be available
	 */

	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		LOG.info("Fetching contacts from " + CONTACTS_URL);
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				CONTACTS_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __myspace.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __myspace,
						token, nts, sig));
		Response serviceResponse = null;
		try {
			serviceResponse = connector.doGET(serviceParams.toStringRFC3986(),
					authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the user contacts from  "
					+ CONTACTS_URL,
					ie);
		}

		StringBuffer sb = new StringBuffer();
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					serviceResponse.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			LOG.debug("Contacts JSON :" + sb.toString());
		} catch (Exception exc) {
			throw new SocialAuthException("Failed to read contacts from  "
					+ CONTACTS_URL);
		}
		JSONArray fArr = new JSONArray();
		JSONObject resObj = new JSONObject(sb.toString());
		if (resObj.has("entry")) {
			fArr = resObj.getJSONArray("entry");
		} else {
			throw new ServerDataException(
					"Failed to parse the user Contacts json : " + sb.toString());
		}
		List<Contact> plist = new ArrayList<Contact>();
		for (int i = 0; i < fArr.length(); i++) {
			JSONObject fObj = fArr.getJSONObject(i);
			if (fObj.has("person")) {
				Contact contact = new Contact();
				JSONObject pObj = fObj.getJSONObject("person");
				if (pObj.has("displayName")) {
					contact.setDisplayName(pObj.getString("displayName"));
				}
				if (pObj.has("name")) {
					JSONObject nobj = pObj.getJSONObject("name");
					if (nobj.has("familyName")) {
						contact.setLastName(nobj.getString("familyName"));
					}
					if (nobj.has("givenName")) {
						contact.setFirstName(nobj.getString("givenName"));
					}
				}

				if (pObj.has("profileUrl")) {
					contact.setProfileUrl(pObj.getString("profileUrl"));
				}
				plist.add(contact);
			}
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
		LOG.info("Updating status " + msg + " on " + UPDATE_STATUS_URL);

		long randomNum = new Random().nextLong();
		long timestamp = System.currentTimeMillis()/1000;
		Map<String, String> args = new HashMap<String, String>();
		args.put(Constants.OAUTH_CONSUMER_KEY, __myspace
				.getConsumerKey());
		args.put(Constants.OAUTH_NONCE, Long.toString(randomNum));
		args.put(Constants.OAUTH_SIGNATURE_METHOD, "HMAC-SHA1");
		args.put(Constants.OAUTH_TIMESTAMP, Long.toString(timestamp));
		args.put(Constants.OAUTH_VERSION, "1.0");
		args.put(Constants.OAUTH_TOKEN, token.getKey());
		OAuthConsumer oauthConsumer = new OAuthConsumer();
		oauthConsumer.setConsumerSecret(__myspace.getConsumerSecret());
		oauthConsumer.setTokenSecret(token.getSecret());
		String sig1 = oauthConsumer.generateSignature(__myspace.getSignature()
				.getMethod(), "PUT", UPDATE_STATUS_URL, args);
		String result = UPDATE_STATUS_URL + "?"
		+ oauthConsumer.buildParams(args) + "&"
		+ Constants.OAUTH_SIGNATURE + "=" + oauthConsumer.encode(sig1);

		HashMap<String, String> headerMap = new HashMap<String, String>();
		String msgBody = "{\"status\":\"" + msg + "\"}";
		String response = doHttpMethodReq(result, "PUT", msgBody, headerMap);
		LOG.info("Update Status Response :" + response);

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

	private Profile getUserProfile() throws Exception {
		LOG.debug("Obtaining user profile");
		Profile profile = new Profile();
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				PROFILE_URL);
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __myspace.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __myspace,
						token, nts, sig));
		Response serviceResponse = null;
		try {
			serviceResponse = connector.doGET(serviceParams.toStringRFC3986(),
					authorizationHeader);
		} catch (IOException ie) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + PROFILE_URL,
					ie);
		}
		if (serviceResponse.getStatus() != 200) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + PROFILE_URL
					+ ". Staus :" + serviceResponse.getStatus());
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
					+ PROFILE_URL);
		}
		JSONObject pObj = new JSONObject();
		JSONObject jobj = new JSONObject(sb.toString());
		if (jobj.has("person")) {
			pObj = jobj.getJSONObject("person");
		} else {
			throw new ServerDataException(
					"Failed to parse the user profile json : " + sb.toString());
		}
		if (pObj.has("displayName")) {
			profile.setDisplayName(pObj.getString("displayName"));
		}
		if (pObj.has("id")) {
			profile.setValidatedId(pObj.getString("id"));
		}
		if (pObj.has("name")) {
			JSONObject nobj = pObj.getJSONObject("name");
			if (nobj.has("familyName")) {
				profile.setLastName(nobj.getString("familyName"));
			}
			if (nobj.has("givenName")) {
				profile.setFirstName(nobj.getString("givenName"));
			}
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
		if (pObj.has("thumbnailUrl")) {
			profile.setProfileImageURL(pObj.getString("thumbnailUrl"));
		}

		return profile;
	}

	private void restore() throws Exception {
		try {
			__myspace = Endpoint.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		__consumer = Consumer.newInstance(this.properties);
	}





	public String doHttpMethodReq(String urlStr, String requestMethod,
			String paramStr, Map<String, String> header) throws Exception {
		StringBuffer sb = new StringBuffer();
		try {
			// Construct data
			// Send data
			URL url = new URL(urlStr);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setDoOutput(true);
			conn.setDoInput(true);
			if (requestMethod != null) {
				conn.setRequestMethod(requestMethod);
			}

			if (header != null) {
				for (String key : header.keySet()) {
					conn.setRequestProperty(key, header.get(key));
				}
			}

			// conn.setRequestProperty("X-HTTP-Method-Override", "PUT"); // If
			// use POST, must use this

			OutputStreamWriter wr = null;
			if (requestMethod != null && !requestMethod.equals("GET")
					&& !requestMethod.equals("DELETE")) {
				wr = new OutputStreamWriter(conn.getOutputStream());
				wr.write(paramStr);
				wr.flush();
			}
			if (conn.getResponseCode() != 200) {
				throw new SocialAuthException(
						"Failed to update status. Return status code :"
						+ conn.getResponseCode());
			}
			// Get the response
			BufferedReader br = new BufferedReader(new InputStreamReader(conn
					.getInputStream()));
			do {
				String line = null;
				try {
					line = br.readLine();
				} catch (IOException e) {
					throw e;
				}

				if (line == null) {
					break;
				}
				sb.append(line).append("\n");
			} while (true);

			if (wr != null) {
				wr.close();
			}
			if (br != null) {
				br.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		String response = sb.toString();
		return response;
	}
}
