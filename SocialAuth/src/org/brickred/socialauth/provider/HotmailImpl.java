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
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
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
import org.json.JSONArray;
import org.json.JSONObject;

import com.dyuproject.oauth.Constants;
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

public class HotmailImpl extends AbstractProvider implements AuthProvider,
Serializable {

	private static final long serialVersionUID = 4559561466129062485L;
	private static final String CONSENT_URL = "https://consent.live.com/Connect.aspx?wrap_client_id=%1$s&wrap_callback=%2$s";
	private static final String ACCESS_TOKEN_URL = "https://consent.live.com/AccessToken.aspx";
	private static final String PROFILE_URL = "http://apis.live.net/V4.1/cid-%1$s/Profiles/1-%2$s";
	private static final String CONTACTS_URL = "http://apis.live.net/V4.1/cid-%1$s/Contacts/AllContacts?$type=portable";
	private static final String UPDATE_STATUS_URL = "http://apis.live.net/V4.1/cid-%1$s/MyActivities";
	private static final String PROPERTY_DOMAIN = "consent.live.com";
	private final Log LOG = LogFactory.getLog(HotmailImpl.class);

	transient private Endpoint __hotmail;
	transient private boolean unserializedFlag;

	private String accessToken;
	private String appid;
	private String secret;
	private String uid;
	private String redirectUri;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;


	public HotmailImpl(final Properties props)
	throws Exception {
		try {
			__hotmail = Endpoint.load(props, PROPERTY_DOMAIN);
			this.properties = props;
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		secret = __hotmail.getConsumerSecret();
		appid = __hotmail.getConsumerKey();
		if (secret.length() == 0) {
			throw new SocialAuthConfigurationException(
					"consent.live.com.consumer_secret value is null");
		}
		if (appid.length() == 0) {
			throw new SocialAuthConfigurationException(
			"consent.live.com.consumer_key value is null");
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

	@Override
	public String getLoginRedirectURL(final String redirectUri)
	throws Exception {
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		this.redirectUri = redirectUri;
		String consentUrl = String.format(CONSENT_URL, appid, redirectUri);
		if (!Permission.AUHTHENTICATE_ONLY.equals(scope)) {
			consentUrl+= "&wrap_scope=WL_Contacts.View,WL_Activities.Update";
		}
		LOG.info("Redirection to following URL should happen : " + consentUrl);
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

	@Override
	public Profile verifyResponse(final HttpServletRequest request)
	throws Exception {
		LOG.info("Retrieving Access Token in verify response function");
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		if (!unserializedFlag) {
			restore();
		}
		String code = request.getParameter("wrap_verification_code");
		if (code == null || code.length() == 0) {
			throw new SocialAuthException("Verification code is null");
		}
		HttpURLConnection conn;
		URL url = new URL(ACCESS_TOKEN_URL);
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
		conn.setDoOutput(true);
		conn.setDoInput(true);
		OutputStreamWriter wr = null;
		StringBuilder strb = new StringBuilder();
		strb.append("wrap_client_id=").append(appid);
		strb.append("&wrap_client_secret=").append(secret);
		strb.append("&wrap_callback=").append(redirectUri);
		strb.append("&wrap_verification_code=").append(code);
		strb.append("&idtype=CID");
		System.out.println("====SBB===="+strb.toString());
		wr = new OutputStreamWriter(conn.getOutputStream());
		wr.write(strb.toString());
		wr.flush();
		conn.connect();
			
		int returnCode = conn.getResponseCode();
		String result = null;
		if (returnCode == 200) {
			StringBuffer sb = new StringBuffer();
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(
						conn.getInputStream(), Constants.ENCODING));
				String line = null;
				while ((line = reader.readLine()) != null) {
					sb.append(line);
				}
			} catch (Exception exc) {
				throw new SocialAuthException("Failed to parse response");
			}
			result = sb.toString();
		}
		if (result == null || result.length() == 0) {
			throw new SocialAuthConfigurationException(
					"Problem in getting Access Token. Application key or Secret key may be wrong."
					+ "The server running the application should be same that was registered to get the keys.");
		}

		try {
			Integer expires = null;
			String[] pairs = result.split("&");
			for (String pair : pairs) {
				String[] kv = pair.split("=");
				if (kv.length != 2) {
					throw new SocialAuthException(
							"Unexpected auth response from " + ACCESS_TOKEN_URL);
				} else {
					if (kv[0].equals("wrap_access_token")) {
						accessToken = kv[1];
					}
					if (kv[0].equals("wrap_access_token_expires_in")) {
						expires = Integer.valueOf(kv[1]);
					}
					if (kv[0].equals("uid")) {
						uid = kv[1];
					}
					LOG.debug("Access Token : " + accessToken);
					LOG.debug("Expires : " + expires);
				}
			}
			if (accessToken != null && expires != null) {
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
			//method.releaseConnection();
			conn.disconnect();
		}

	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * 
	 * @return List of profile objects representing Contacts. Only name and
	 *         email will be available
	 * @throws Exception
	 */

	@Override
	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		String u = String.format(CONTACTS_URL, uid);
		LOG.info("Fetching contacts from " + u);
		HttpURLConnection conn;
		URL url = new URL(u);
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setRequestProperty("Authorization", "WRAP access_token="+ accessToken);
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("Accept", "application/json");
		//conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.connect();
		int returnCode = conn.getResponseCode();
		if (returnCode != 200) {
			throw new SocialAuthException("Error while getting contacts from "
					+ u + "Status : " + returnCode);
		}
		StringBuffer sb = new StringBuffer();
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
		} catch (Exception e) {
			throw new ServerDataException("Failed to get response from " + u);
		}
		LOG.debug("User Contacts list in JSON " + sb.toString());
		JSONObject resp = new JSONObject(sb.toString());
		List<Contact> plist = new ArrayList<Contact>();
		if (resp.has("entries")) {
			JSONArray addArr = resp.getJSONArray("entries");
			LOG.debug("Contacts Found : " + addArr.length());
			for (int i = 0; i < addArr.length(); i++) {
				JSONObject obj = addArr.getJSONObject(i);
				if (obj.has("emails")) {
					JSONArray emailArr = obj.getJSONArray("emails");
					int emailCount = emailArr.length();
					if (emailCount > 0) {
						Contact p = new Contact();
						JSONObject eobj = emailArr.getJSONObject(0);
						if (eobj.has("value")) {
							p.setEmail(eobj.getString("value"));
						}
						if (emailCount > 1) {
							String sarr[] = new String[emailCount - 1];
							for (int k = 0; k < emailCount - 1; k++) {
								eobj = emailArr.getJSONObject(k + 1);
								if (eobj.has("value")) {
									sarr[k] = eobj.getString("value");
								}
							}
							p.setOtherEmails(sarr);
						}
						if (obj.has("name")) {
							JSONObject nameObj = obj.getJSONObject("name");
							if (nameObj.has("familyName")) {
								p.setLastName(nameObj.getString("familyName"));
							}
							if (nameObj.has("formatted")) {
								p
								.setDisplayName(nameObj
										.getString("formatted"));
							}
							if (nameObj.has("givenName")) {
								p.setFirstName(nameObj.getString("givenName"));
							}
						}
						plist.add(p);
					}
				}
			}

		}
		conn.disconnect();
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
	@Override
	public void updateStatus(final String msg) throws Exception {
		LOG.info("Updating status : " + msg);
		if (!isVerify) {
			throw new SocialAuthException(
			"Please call verifyResponse function first to get Access Token");
		}
		if (msg == null || msg.trim().length() == 0) {
			throw new ServerDataException("Status cannot be blank");
		}
		String u = String.format(UPDATE_STATUS_URL, uid);
		HttpURLConnection conn;
		URL url = new URL(u);
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.setRequestProperty("Authorization", "WRAP access_token="+ accessToken);
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("Accept", "application/json");
		String body = "{\"__type\" : \"AddStatusActivity:http://schemas.microsoft.com/ado/2007/08/dataservices\",\"ActivityVerb\" : \"http://activitystrea.ms/schema/1.0/post\",\"ApplicationLink\" : \"http://rex.mslivelabs.com\",\"ActivityObjects\" : [{\"ActivityObjectType\" : \"http://activitystrea.ms/schema/1.0/status\",\"Content\" : \""+ msg+ "\",\"AlternateLink\" : \"http://www.contoso.com/wp-content/uploads/2009/06/comments-icon.jpg\"}}]}";
		conn.setRequestProperty("Content-Length", new Integer(body.length()).toString());
		OutputStreamWriter wr = null;
		wr = new OutputStreamWriter(conn.getOutputStream());
		wr.write(body);
		wr.flush();
		conn.connect();
		
		int code = conn.getResponseCode();
		LOG.debug("Status updated and return status code is :" + code);
		// return 201
		conn.disconnect();
	}

	/**
	 * Logout
	 */
	@Override
	public void logout() {
		accessToken = null;
	}

	private Profile getUserProfile() throws Exception {
		Profile p = new Profile();
		String u = String.format(PROFILE_URL, uid, uid);
		HttpURLConnection conn;
		URL url = new URL(u);
		conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setDoInput(true);
		conn.setRequestProperty("Authorization", "WRAP access_token="+ accessToken);
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("Accept", "application/json");
		
		try {
			conn.connect();
		} catch (Exception e) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + u, e);
		}
		StringBuffer sb = new StringBuffer();
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					conn.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			LOG.debug("User Profile :" + sb.toString());
		} catch (Exception e) {
			throw new SocialAuthException("Failed to read response from  " + u);
		}
		try {
			JSONObject resp = new JSONObject(sb.toString());
			if (resp.has("Id")) {
				p.setValidatedId(resp.getString("Id"));
			}
			if (resp.has("FirstName")) {
				p.setFirstName(resp.getString("FirstName"));
			}
			if (resp.has("LastName")) {
				p.setLastName(resp.getString("LastName"));
			}
			if (resp.has("Location")) {
				p.setLocation(resp.getString("Location"));
			}
			if (resp.has("Gender")) {
				String g = resp.getString("Gender");
				if ("1".equals(g)) {
					p.setGender("Female");
				} else if ("2".equals(g)) {
					p.setGender("Male");
				}
			}
			if (resp.has("ThumbnailImageLink")) {
				p.setProfileImageURL(resp.getString("ThumbnailImageLink"));
			}

			if (resp.has("Emails")) {
				JSONArray earr = resp.getJSONArray("Emails");
				for (int i = 0; i < earr.length(); i++) {
					JSONObject eobj = earr.getJSONObject(i);
					if (eobj.has("Type") && "1".equals(eobj.getString("Type"))) {
						p.setEmail(eobj.getString("Address"));
						break;
					}
				}
				if (p.getEmail() == null || p.getEmail().length() <= 0) {
					JSONObject eobj = earr.getJSONObject(0);
					p.setEmail(eobj.getString("Address"));
				}
			}
			conn.disconnect();
			return p;
		} catch (Exception e) {
			throw new SocialAuthException(
					"Failed to parse the user profile json : " + sb.toString());
		}
	}

	/**
	 * 
	 * @param p
	 *            Permission object which can be Permission.AUHTHENTICATE_ONLY,
	 *            Permission.ALL, Permission.DEFAULT
	 */
	public void setPermission(final Permission p) {
		this.scope = p;
	}

	private void restore() throws Exception {
		try {
			__hotmail = Endpoint.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
	}
}
