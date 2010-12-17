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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Contact;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.json.JSONArray;
import org.json.JSONObject;

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
	private String accessToken;
	private String appid;
	private String secret;
	private String uid;
	private final Endpoint __hotmail;
	private WindowsLiveLogin wll;
	private String redirectUri;
	private int scope;

	public HotmailImpl(final Properties props, final int scope)
	throws Exception {
		try {
			__hotmail = Endpoint.load(props, "consent.live.com");
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
		this.scope = scope;

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
		this.redirectUri = redirectUri;
		String consentUrl = "https://consent.live.com/Connect.aspx?wrap_client_id="
				+ appid + "&wrap_callback=" + redirectUri;
		if (scope == AuthProvider.ALL_PERMISSIONS) {
			consentUrl+= "&wrap_scope=WL_Contacts.View,WL_Activities.Update";
		}
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
		String authURL = "https://consent.live.com/AccessToken.aspx";
		String code = request.getParameter("wrap_verification_code");
		if (code == null || code.length() == 0) {
			throw new SocialAuthException("Verification code is null");
		}
		HttpClient client = new HttpClient();
		PostMethod method = new PostMethod(authURL);
		method.addParameter("wrap_client_id", appid);
		method.addParameter("wrap_client_secret", secret);
		method.addParameter("wrap_callback", redirectUri);
		method.addParameter("wrap_verification_code", code);
		method.addParameter("idtype", "CID");
		int returnCode = client.executeMethod(method);
		if (returnCode != HttpStatus.SC_OK) {
			throw new SocialAuthException(
			"Problem in getting Access Token. Application key or Secret key may be wrong. Please verify your keys in property file");
		}
		String result = null;
		try {
			result = method.getResponseBodyAsString();
		} catch (IOException e) {
			throw new SocialAuthException("Unable to retrieve Access Token.", e);
		}
		try {
			Integer expires = null;
			String[] pairs = result.split("&");
			for (String pair : pairs) {
				String[] kv = pair.split("=");
				if (kv.length != 2) {
					throw new RuntimeException("Unexpected auth response");
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
				}
			}
			if (accessToken != null && expires != null) {
				Profile p = getUserProfile();
				return p;

			} else {
				throw new RuntimeException("Access token and expires not found");
			}
		} catch (Exception e) {
			throw e;
		} finally {
			method.releaseConnection();
		}

	}

	/**
	 * Gets the list of contacts of the user and their email.
	 * @return List of profile objects representing Contacts. Only name and email
	 * will be available
	 */

	public List<Contact> getContactList() throws Exception {
		HttpClient client = new HttpClient();
		String u = "http://apis.live.net/V4.1/cid-" + uid
		+ "/Contacts/AllContacts?$type=portable";
		GetMethod get = new GetMethod(u);
		get.addRequestHeader("Authorization", "WRAP access_token="
				+ accessToken);
		get.addRequestHeader("Content-Type", "application/json");
		get.addRequestHeader("Accept", "application/json");
		// TODO:it should be in separate try/catch
		int returnCode = client.executeMethod(get);
		if (returnCode != HttpStatus.SC_OK) {
			throw new SocialAuthException("Problem in getting Contacts");
		}
		StringBuffer sb = new StringBuffer();
		// TODO:chek this need for try or not
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					get.getResponseBodyAsStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
		} catch (Exception e) {
			throw e;
		}
		JSONObject resp = new JSONObject(sb.toString());
		List<Contact> plist = new ArrayList<Contact>();
		if (resp.has("entries")) {
			JSONArray addArr = resp.getJSONArray("entries");
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
		return plist;
	}


	public void updateStatus(final String msg) throws Exception {
		System.out.println("WARNING: not implemented");
		String url = "http://apis.live.net/V4.1/cid-" + uid + "/MyActivities";
		HttpClient client = new HttpClient();
		PostMethod method = new PostMethod(url);
		method.addRequestHeader("Authorization", "WRAP access_token="
				+ accessToken);
		method.addRequestHeader("Content-Type", "application/json");
		method.addRequestHeader("Accept", "application/json");
		JSONObject jbody = new JSONObject();
		jbody
		.put("_type",
		"AddStatusActivity:http://schemas.microsoft.com/ado/2007/08/dataservices");
		jbody.put("ActivityVerb", "http://activitystrea.ms/schema/1.0/post");
		jbody.put("ApplicationLink", "http://rex.mslivelabs.com");
		JSONObject aobj = new JSONObject();
		aobj.put("ActivityObjectType",
		"http://activitystrea.ms/schema/1.0/status");
		aobj.put("Content", msg);
		aobj
		.put("AlternateLink",
		"http://www.contoso.com/wp-content/uploads/2009/06/comments-icon.jpg");
		JSONArray activityArr = new JSONArray();
		activityArr.put(aobj);

		jbody.put("ActivityObjects", activityArr);
		System.out.println("----------BODY-----------" + jbody.toString());

		String body = "{\"__type\" : \"AddStatusActivity:http://schemas.microsoft.com/ado/2007/08/dataservices\",\"ActivityVerb\" : \"http://activitystrea.ms/schema/1.0/post\",\"ApplicationLink\" : \"http://rex.mslivelabs.com\",\"ActivityObjects\" : [{\"ActivityObjectType\" : \"http://activitystrea.ms/schema/1.0/status\",\"Content\" : \""
			+ "Tis is new one"
			+ "\",\"AlternateLink\" : \"http://www.contoso.com/wp-content/uploads/2009/06/comments-icon.jpg\"}}]}";
		String bstr = jbody.toString();
		method.addRequestHeader("Content-Length", new Integer(bstr.length())
		.toString());
		method.setRequestEntity(new StringRequestEntity(bstr,
				"application/json", "UTF-8"));
		int code = client.executeMethod(method);
		System.out.println("-------------" + code + "---------------");
		StringBuffer sb = new StringBuffer();
		BufferedReader reader = new BufferedReader(new InputStreamReader(method
				.getResponseBodyAsStream(), "UTF-8"));
		String line = null;
		while ((line = reader.readLine()) != null) {
			sb.append(line).append("\n");
		}
		System.out
		.println("------------START STATUS RESPONSE---------------------");
		System.out.println(sb.toString());
		System.out
		.println("------------END STATUS RESPONSE---------------------");
	}

	/**
	 * Logout
	 */
	public void logout() {
		token = null;
	}

	private Profile getUserProfile() {
		Profile p = new Profile();
		HttpClient client = new HttpClient();
		String u = "http://apis.live.net/V4.1/cid-" + uid + "/Profiles/1-"
		+ uid;
		GetMethod get = new GetMethod(u);
		get.addRequestHeader("Authorization", "WRAP access_token="
				+ accessToken);
		get.addRequestHeader("Content-Type", "application/json");
		get.addRequestHeader("Accept", "application/json");

		try {
			client.executeMethod(get);
			StringBuffer sb = new StringBuffer();
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					get.getResponseBodyAsStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			JSONObject resp = new JSONObject(sb.toString());
			if (resp.has("Id")) {
				p.setValidatedId(resp.getString("Id"));
				// TODO: put CID or ID
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
			return p;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
