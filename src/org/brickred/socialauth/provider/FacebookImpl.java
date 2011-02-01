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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
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
import com.visural.common.IOUtil;
import com.visural.common.StringUtil;

/**
 * Provider implementation for Facebook
 * 
 * @author Abhinav Maheshwari
 * 
 */
public class FacebookImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = 8644510564735754296L;
	private static final String PROPERTY_DOMAIN = "graph.facebook.com";
	private static final String UPDATE_STATUS_URL = "https://graph.facebook.com/me/feed";
	private static final String PROFILE_IMAGE_URL = "http://graph.facebook.com/%1$s/picture";
	private static final String PUBLIC_PROFILE_URL = "http://www.facebook.com/profile.php?id=";
	private final Log LOG = LogFactory.getLog(FacebookImpl.class);

	transient private Endpoint __facebook;
	transient private boolean unserializedFlag;

	private String secret;
	private String client_id;
	private String accessToken;
	private String redirectUri;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;



	/// set this to the list of extended permissions you want
	private static final String[] AllPerms = new String[] { "publish_stream",
		"email", "user_birthday", "user_location" };
	private static final String[] AuthPerms = new String[] { "email",
		"user_birthday", "user_location" };

	/**
	 * Reads properties provided in the configuration file
	 * 
	 * @param props
	 *            Properties for consumer key
	 * @param scope
	 *            scope is a permission setting. It can be
	 *            AuthProvider.AUTHENTICATION_ONLY or
	 *            AuthProvider.ALL_PERMISSIONS
	 */
	public FacebookImpl(final Properties props)
	throws Exception {
		try {
			__facebook = Endpoint.load(props, PROPERTY_DOMAIN);
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		secret = __facebook.getConsumerSecret();
		client_id = __facebook.getConsumerKey();
		if (secret.length() <= 0) {
			throw new SocialAuthConfigurationException(
			"graph.facebook.com.consumer_secret value is null");
		}
		if (client_id.length() <= 0) {
			throw new SocialAuthConfigurationException(
			"graph.facebook.com.consumer_key value is null");
		}
		unserializedFlag = true;
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 */
	public String getLoginRedirectURL(final String redirectUri) {
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		this.redirectUri = redirectUri;
		String url = __facebook.getAuthorizationUrl() + "?client_id="
		+ client_id + "&display=page&redirect_uri=" + redirectUri;
		if (Permission.AUHTHENTICATE_ONLY.equals(scope)) {
			url += "&scope="
				+ StringUtil.delimitObjectsToString(",", AuthPerms);
		} else {
			url += "&scope=" + StringUtil.delimitObjectsToString(",", AllPerms);
		}
		LOG.info("Redirection to following URL should happen : " + url);
		return url;
	}

	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * @return Profile object containing the profile information
	 * @param request Request object the request is received from the provider
	 * @throws Exception
	 */

	public Profile verifyResponse(final HttpServletRequest httpReq)
	throws Exception {
		LOG.info("Retrieving Access Token in verify response function");
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		if (!unserializedFlag) {
			restore();
		}
		String code = httpReq.getParameter("code");
		if (code == null || code.length() == 0) {
			throw new SocialAuthException("Verification code is null");
		}
		LOG.debug("Verification Code : " + code);
		String authURL = getAuthURL(code);
		URL url;
		try {
			url = new URL(authURL);
		} catch (Exception e) {
			throw new SocialAuthException("Error in url : " + authURL, e);
		}
		String result;
		try {
			result = readURL(url);
		} catch (IOException io) {
			throw new SocialAuthException(io);
		}
		Integer expires = null;
		String[] pairs = result.split("&");
		for (String pair : pairs) {
			String[] kv = pair.split("=");
			if (kv.length != 2) {
				throw new SocialAuthException(
						"Unexpected auth response from " + authURL);
			} else {
				if (kv[0].equals("access_token")) {
					accessToken = kv[1];
				}
				if (kv[0].equals("expires")) {
					expires = Integer.valueOf(kv[1]);
				}
				LOG.debug("Access Token : " + accessToken);
				LOG.debug("Expires : " + expires);
			}
		}
		if (accessToken != null && expires != null) {
			isVerify = true;
			LOG.debug("Obtaining user profile");
			return authFacebookLogin(accessToken, expires);
		} else {
			throw new SocialAuthException(
					"Access token and expires not found from " + url);
		}
	}

	private String getAuthURL(final String authCode) {
		String acode;
		try {
			acode = URLEncoder.encode(authCode, "UTF-8");
		} catch (Exception e) {
			acode = authCode;
		}
		return __facebook.getRequestTokenUrl() + "?client_id=" + client_id
		+ "&redirect_uri=" + redirectUri + "&client_secret=" + secret
		+ "&code=" + acode;
	}

	private Profile authFacebookLogin(final String accessToken,
			final int expires) throws Exception {
		String presp;
		String aToken;
		try {
			aToken = URLEncoder.encode(accessToken, "UTF-8");
		} catch (Exception e) {
			aToken = accessToken;
		}
		String url = __facebook.getAccessTokenUrl() + "?access_token=" + aToken;
		try {
			presp = IOUtil.urlToString(new URL(url));
		} catch (Exception e) {
			throw new SocialAuthException("Error while getting profile from "
					+ url, e);
		}
		try {
			LOG.debug("User Profile : " + presp);
			JSONObject resp = new JSONObject(presp);
			Profile p = new Profile();
			p.setValidatedId(resp.getString("id"));
			p.setFirstName(resp.getString("first_name"));
			p.setLastName(resp.getString("last_name"));
			p.setEmail(resp.getString("email"));
			if (resp.has("location")) {
				p.setLocation(resp.getJSONObject("location").getString("name"));
			}
			if (resp.has("birthday")) {
				p.setDob(resp.getString("birthday"));
			}
			if (resp.has("gender")) {
				p.setGender(resp.getString("gender"));
			}
			p.setProfileImageURL(String.format(PROFILE_IMAGE_URL, resp
					.getString("id")));
			String locale = resp.getString("locale");
			if (locale != null) {
				String a[] = locale.split("_");
				p.setLanguage(a[0]);
				p.setCountry(a[1]);
			}

			return p;

		} catch (Exception ex) {
			throw new ServerDataException(
					"Failed to parse the user profile json : " + presp, ex);
		}
	}

	private String readURL(final URL url) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = url.openStream();
		int r;
		while ((r = is.read()) != -1) {
			baos.write(r);
		}
		return new String(baos.toByteArray());
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
		LOG.info("Updating status : " + msg);
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token and then update status");
		}
		if (msg == null || msg.trim().length() == 0) {
			throw new ServerDataException("Status cannot be blank");
		}
		HttpClient client = new HttpClient();
		PostMethod method = new PostMethod(UPDATE_STATUS_URL);
		method.addParameter("access_token", accessToken);
		method.addParameter("message", msg);

		try{
			int returnCode = client.executeMethod(method);
			String rmsg = method.getResponseBodyAsString();

			if(returnCode != HttpStatus.SC_OK) {
				throw new SocialAuthException(
						"Status not updated. Return Status code :" + returnCode
						+ " Message: " + rmsg);
			}
		} catch (Exception e) {
			throw new SocialAuthException(e);
		} finally {
			method.releaseConnection();
		}

	}

	/**
	 * Gets the list of contacts of the user. this may not be available for all
	 * providers.
	 * 
	 * @return List of contact objects representing Contacts. Only name will be
	 *         available
	 */

	public List<Contact> getContactList() throws Exception {
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		List<Contact> plist = new ArrayList<Contact>();
		String contactURL = __facebook.getAccessTokenUrl()
		+ "/friends?access_token=" + accessToken;
		LOG.info("Fetching contacts from " + contactURL);
		String respStr;
		try {
			respStr = IOUtil.urlToString(new URL(contactURL));
		} catch (Exception e) {
			throw new SocialAuthException("Error while getting contacts from "
					+ contactURL);
		}
		try {
			LOG.debug("User Contacts list in json : " + respStr);
			JSONObject resp = new JSONObject(respStr);
			JSONArray data = resp.getJSONArray("data");
			LOG.debug("Found contacts : " + data.length());
			for (int i = 0; i < data.length(); i++) {
				JSONObject obj = data.getJSONObject(i);
				Contact p = new Contact();
				p.setFirstName(obj.getString("name"));
				p.setProfileUrl(PUBLIC_PROFILE_URL + obj.getString("id"));
				plist.add(p);
			}
		} catch (Exception e) {
			throw new ServerDataException(
					"Failed to parse the user profile json : " + respStr, e);
		}
		return plist;
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
			__facebook = Endpoint.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
	}
}