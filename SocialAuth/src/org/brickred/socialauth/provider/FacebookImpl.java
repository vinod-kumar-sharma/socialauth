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
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.ServerDataException;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
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
public class FacebookImpl extends AbstractProvider implements AuthProvider {

	private String secret;
	private String client_id;
	private String accessToken;
	private final Endpoint __facebook;
	private String redirectUri;


	/// set this to the list of extended permissions you want
	private static final String[] perms = new String[] { "publish_stream",
		"email", "user_birthday", "user_location" };

	/**
	 * Reads properties provided in the configuration file
	 * @param props Properties for consumer key
	 */
	public FacebookImpl(final Properties props) throws Exception {
		try {
			__facebook = Endpoint.load(props, "graph.facebook.com");
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
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 */
	public String getLoginRedirectURL(final String redirectUri) {
		setProviderState(true);
		this.redirectUri = redirectUri;
		return __facebook.getAuthorizationUrl() + "?client_id=" +
		client_id + "&display=page&redirect_uri=" +
		redirectUri + "&scope=" + StringUtil.delimitObjectsToString(",", perms);
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
	throws Exception
	{
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		try {
			String code = httpReq.getParameter("code");
			if (code != null && code.length() > 0) {
				String authURL = getAuthURL(code);
				URL url = new URL(authURL);
				try {
					String result = readURL(url);
					Integer expires = null;
					String[] pairs = result.split("&");
					for (String pair : pairs) {
						String[] kv = pair.split("=");
						if (kv.length != 2) {
							throw new RuntimeException("Unexpected auth response");
						} else {
							if (kv[0].equals("access_token")) {
								accessToken = kv[1];
							}
							if (kv[0].equals("expires")) {
								expires = Integer.valueOf(kv[1]);
							}
						}
					}
					if (accessToken != null && expires != null) {
						return authFacebookLogin(accessToken, expires);
					} else {
						throw new RuntimeException("Access token and expires not found");
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}


		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	private String getAuthURL(final String authCode) {
		return __facebook.getRequestTokenUrl() + "?client_id=" + client_id
		+ "&redirect_uri=" + redirectUri + "&client_secret=" + secret
		+ "&code=" + authCode;
	}

	private Profile authFacebookLogin(final String accessToken, final int expires) {
		try {
			JSONObject resp = new JSONObject(IOUtil.urlToString(new URL(
					__facebook.getAccessTokenUrl() + "?access_token="
					+ accessToken)));
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
			p.setProfileImageURL("http://graph.facebook.com/"
					+ resp.getString("id")
					+ "/picture");
			String locale = resp.getString("locale");
			if (locale != null) {
				String a[] = locale.split("_");
				p.setLanguage(a[0]);
				p.setCountry(a[1]);
			}

			return p;

		} catch (Throwable ex) {
			ex.printStackTrace();
			throw new RuntimeException("failed login", ex);
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
	 * @param msg Message to be shown as user's status
	 */

	public void updateStatus(final String msg) {
		HttpClient client = new HttpClient();
		PostMethod method = new PostMethod("https://graph.facebook.com/me/feed");
		method.addParameter("access_token", accessToken);
		method.addParameter("message", msg);

		try{
			int returnCode = client.executeMethod(method);
			method.getResponseBodyAsString();

			if(returnCode != HttpStatus.SC_OK) {
				throw new Exception("Status not updated");
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			method.releaseConnection();
		}

	}

	/**
	 * Gets the list of contacts of the user and their email. this may not
	 * be available for all providers.
	 * @return List of profile objects representing Contacts. Only name and email
	 * will be available
	 */

	public List<Profile> getContactList() throws Exception {
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		List<Profile> plist = new ArrayList<Profile>();
		String contactURL = __facebook.getAccessTokenUrl()
		+ "/friends?access_token=" + accessToken;
		try {
			JSONObject resp = new JSONObject(IOUtil.urlToString(new URL(
					contactURL)));
			JSONArray data = resp.getJSONArray("data");
			for (int i = 0; i < data.length(); i++) {
				JSONObject obj = data.getJSONObject(i);
				Profile p = new Profile();
				p.setFirstName(obj.getString("name"));
				plist.add(p);
			}
		} catch (Exception e) {
			throw new ServerDataException("Problem in getting contacts from "
					+ contactURL, e);
		}
		return plist;
	}

	/**
	 * Logout
	 */
	public void logout() {
		accessToken = null;
	}
}