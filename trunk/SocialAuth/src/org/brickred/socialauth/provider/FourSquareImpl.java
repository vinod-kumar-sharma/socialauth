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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
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
import org.json.JSONArray;
import org.json.JSONObject;

import com.dyuproject.oauth.Endpoint;

/**
 * Provider implementation for FourSquare. This uses the oAuth API provided by
 * FourSquare
 * 
 * @author tarunn@brickred.com
 * 
 */
public class FourSquareImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = 903564874550419470L;
	private static final String PROFILE_URL = "https://api.foursquare.com/v2/users/self?oauth_token=";
	private static final String CONTACTS_URL = "https://api.foursquare.com/v2/users/self/friends?oauth_token=";
	private static final String REQUEST_TOKEN_URL = "https://foursquare.com/oauth2/authenticate?client_id=%1$s&response_type=code&redirect_uri=%2$s";
	private static final String ACCESS_TOKEN_URL = "https://foursquare.com/oauth2/access_token";
	private static final String VIEW_PROFILE_URL = "http://foursquare.com/user/";
	private static final String PROPERTY_DOMAIN = "foursquare.com";

	private final Log LOG = LogFactory.getLog(YahooImpl.class);

	transient private Endpoint __foursquare;
	transient private boolean unserializedFlag;

	private Permission scope;
	private Properties properties;
	private boolean isVerify;
	private String redirectUri;
	private String accessToken;


	public FourSquareImpl(final Properties props) throws Exception {
		try {
			__foursquare = Endpoint.load(props, PROPERTY_DOMAIN);
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (__foursquare.getConsumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
			"foursquare.com.consumer_secret value is null");
		}
		if (__foursquare.getConsumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
			"foursquare.com.consumer_key value is null");
		}
		unserializedFlag = true;
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
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		this.redirectUri = redirectUri;
		String reqTokenUrl = String.format(REQUEST_TOKEN_URL, __foursquare
				.getConsumerKey(), redirectUri);
		LOG.info("Redirection to following URL should happen : " + reqTokenUrl);
		return reqTokenUrl;

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

		String code = request.getParameter("code");
		if (code == null || code.length() == 0) {
			throw new SocialAuthException("Verification code is null");
		}
		HttpClient client = new HttpClient();
		PostMethod method = new PostMethod(ACCESS_TOKEN_URL);
		method.addParameter("client_id", __foursquare.getConsumerKey());
		method.addParameter("client_secret", __foursquare.getConsumerSecret());
		method.addParameter("grant_type", "authorization_code");
		method.addParameter("redirect_uri", redirectUri);
		method.addParameter("code", code);
		int returnCode = client.executeMethod(method);
		String result = null;
		if (returnCode == HttpStatus.SC_OK) {
			result = method.getResponseBodyAsString();
		}
		if (result == null || result.length() == 0) {
			throw new SocialAuthConfigurationException(
					"Problem in getting Access Token. Application key or Secret key may be wrong."
					+ "The server running the application should be same that was registered to get the keys.");
		}

		try {
			JSONObject jobj = new JSONObject(result);
			if(jobj.has("access_token")){
				accessToken = jobj.getString("access_token");
			}
			if (accessToken != null) {
				isVerify = true;
				LOG.debug("Obtaining user profile");
				Profile p = getUserProfile();
				return p;

			} else {
				throw new SocialAuthException(
						"Access token and expires not found from "
						+ ACCESS_TOKEN_URL);
			}
		} catch (Exception e) {
			throw e;
		} finally {
			method.releaseConnection();
		}
		// return null;
	}

	private Profile getUserProfile() throws Exception {
		LOG.debug("Obtaining user profile");
		Profile profile = new Profile();
		HttpClient client = new HttpClient();
		String u = PROFILE_URL + accessToken;
		GetMethod get = new GetMethod(u);
		try {
			client.executeMethod(get);
		} catch (Exception e) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + u, e);
		}
		String res;
		try {
			res = get.getResponseBodyAsString();
			LOG.debug("User Profile :" + res);
		} catch (Exception e) {
			throw new SocialAuthException("Failed to read response from  " + u);
		}

		JSONObject jobj = new JSONObject(res);
		JSONObject rObj;
		JSONObject uObj;
		if (jobj.has("response")) {
			rObj = jobj.getJSONObject("response");
		} else {
			throw new SocialAuthException(
					"Failed to parse the user profile json : " + res);
		}
		if (rObj.has("user")) {
			uObj = rObj.getJSONObject("user");
		} else {
			throw new SocialAuthException(
					"Failed to parse the user profile json : " + res);
		}
		if (uObj.has("id")) {
			profile.setValidatedId(uObj.getString("id"));
		}
		if (uObj.has("firstName")) {
			profile.setFirstName(uObj.getString("firstName"));
		}
		if (uObj.has("lastName")) {
			profile.setLastName(uObj.getString("lastName"));
		}
		if (uObj.has("photo")) {
			profile.setProfileImageURL(uObj.getString("photo"));
		}
		if (uObj.has("gender")) {
			profile.setGender(uObj.getString("gender"));
		}
		if (uObj.has("homeCity")) {
			profile.setLocation(uObj.getString("homeCity"));
		}
		if (uObj.has("contact")) {
			JSONObject cobj = uObj.getJSONObject("contact");
			if (cobj.has("email")) {
				profile.setEmail(cobj.getString("email"));
			}
		}

		return profile;
	}

	/**
	 * Gets the list of contacts of the user.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         profile URL will be available
	 */

	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		String url = CONTACTS_URL + accessToken;
		HttpClient client = new HttpClient();
		LOG.info("Fetching contacts from " + url);
		GetMethod get = new GetMethod(url);

		int returnCode;
		try {
			returnCode = client.executeMethod(get);
		} catch (Exception e) {
			throw new SocialAuthException("Error while getting contacts from "+ url);
		}
		if (returnCode != HttpStatus.SC_OK) {
			throw new SocialAuthException("Error while getting contacts from "
					+ url + "Status : " + returnCode);
		}
		String respStr;
		try {
			respStr = get.getResponseBodyAsString();
		} catch (Exception e) {
			throw new ServerDataException("Failed to get response from " + url);
		}
		LOG.debug("User Contacts list in JSON " + respStr);
		JSONObject resp = new JSONObject(respStr);
		List<Contact> plist = new ArrayList<Contact>();
		JSONArray items = new JSONArray();
		if (resp.has("response")) {
			JSONObject robj = resp.getJSONObject("response");
			if(robj.has("friends")){
				JSONObject fobj = robj.getJSONObject("friends");
				if (fobj.has("items")) {
					items = fobj.getJSONArray("items");
				}
			}else{
				throw new SocialAuthException("Failed to parse the user profile json : " + respStr);
			}
		}else{
			throw new SocialAuthException("Failed to parse the user profile json : " + respStr);
		}
		LOG.debug("Contacts Found : " + items.length());
		for (int i = 0; i < items.length(); i++) {
			JSONObject obj = items.getJSONObject(i);
			Contact c = new Contact();
			if (obj.has("firstName")) {
				c.setFirstName(obj.getString("firstName"));
			}
			if (obj.has("lastName")) {
				c.setLastName(obj.getString("lastName"));
			}
			if (obj.has("id")) {
				c.setProfileUrl(VIEW_PROFILE_URL + obj.getString("id"));
			}
			plist.add(c);
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
		LOG.warn("WARNING: Not implemented for FourSquare");
		throw new SocialAuthException(
		"Update Status is not implemented for FourSquare");
	}

	/**
	 * Logout
	 */
	public void logout() {
		accessToken = null;
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
			__foursquare = Endpoint.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
	}




}
