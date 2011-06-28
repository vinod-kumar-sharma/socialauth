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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Contact;
import org.brickred.socialauth.Permission;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.brickred.socialauth.exception.UserDeniedPermissionException;
import org.brickred.socialauth.util.AccessGrant;
import org.brickred.socialauth.util.Constants;
import org.brickred.socialauth.util.HttpUtil;
import org.brickred.socialauth.util.MethodType;
import org.brickred.socialauth.util.OAuthConfig;
import org.brickred.socialauth.util.Response;
import org.brickred.socialauth.util.SocialAuthUtil;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Provider implementation for FourSquare. This uses the oAuth API provided by
 * FourSquare
 * 
 * @author tarunn@brickred.com
 * 
 */
public class FourSquareImpl extends AbstractProvider implements AuthProvider,
		Serializable {

	private static final long serialVersionUID = 3364430495809289118L;
	private static final String PROFILE_URL = "https://api.foursquare.com/v2/users/self?oauth_token=";
	private static final String CONTACTS_URL = "https://api.foursquare.com/v2/users/self/friends?oauth_token=";
	private static final String REQUEST_TOKEN_URL = "https://foursquare.com/oauth2/authenticate?client_id=%1$s&response_type=code&redirect_uri=%2$s";
	private static final String ACCESS_TOKEN_URL = "https://foursquare.com/oauth2/access_token";
	private static final String VIEW_PROFILE_URL = "http://foursquare.com/user/";
	private final Log LOG = LogFactory.getLog(FourSquareImpl.class);

	private Permission scope;
	private boolean isVerify;
	private String successUrl;
	private String accessToken;
	private OAuthConfig config;
	private Profile userProfile;
	private AccessGrant accessGrant;

	/**
	 * Stores configuration for the provider
	 * 
	 * @param providerConfig
	 *            It contains the configuration of application like consumer key
	 *            and consumer secret
	 * @throws Exception
	 */
	public FourSquareImpl(final OAuthConfig providerConfig) throws Exception {
		config = providerConfig;
	}

	/**
	 * Stores access grant for the provider
	 * 
	 * @param accessGrant
	 *            It contains the access token and other information
	 * @throws Exception
	 */
	@Override
	public void setAccessGrant(final AccessGrant accessGrant) throws Exception {
		this.accessGrant = accessGrant;
		accessToken = accessGrant.getKey();
		isVerify = true;
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	@Override
	public String getLoginRedirectURL(final String successUrl)
			throws Exception {
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		try {
			this.successUrl = URLEncoder.encode(successUrl,
					Constants.ENCODING);
		} catch (UnsupportedEncodingException e) {
			this.successUrl = successUrl;
		}
		String reqTokenUrl = String.format(REQUEST_TOKEN_URL,
				config.get_consumerKey(), this.successUrl);
		LOG.info("Redirection to following URL should happen : " + reqTokenUrl);
		return reqTokenUrl;

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
		Map<String, String> params = SocialAuthUtil
				.getRequestParametersMap(request);
		return doVerifyResponse(params);
	}

	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * @return Profile object containing the profile information
	 * @param requestParams
	 *            Request Parameters, received from the provider
	 * @throws Exception
	 */
	@Override
	public Profile verifyResponse(final Map<String, String> requestParams)
			throws Exception {
		return doVerifyResponse(requestParams);
	}

	private Profile doVerifyResponse(final Map<String, String> requestParams)
			throws Exception {
		LOG.info("Verifying the authentication response from provider");
		if (requestParams.get("error") != null
				&& "access_denied".equals(requestParams.get("error"))) {
			throw new UserDeniedPermissionException();
		}

		if (!isProviderState()) {
			throw new ProviderStateException();
		}

		String code = requestParams.get("code");
		if (code == null || code.length() == 0) {
			throw new SocialAuthException("Verification code is null");
		}
		StringBuilder strb = new StringBuilder();
		strb.append("client_id=").append(config.get_consumerKey()).append("&");
		strb.append("client_secret=").append(config.get_consumerSecret())
				.append("&");
		strb.append("grant_type=authorization_code&");
		strb.append("redirect_uri=").append(successUrl).append("&");
		strb.append("code=").append(code);
		Response serviceResponse = HttpUtil.doHttpRequest(ACCESS_TOKEN_URL,
				MethodType.POST.toString(), strb.toString(), null);

		String result = null;
		if (serviceResponse.getStatus() == 200) {
			try {
				result = serviceResponse
						.getResponseBodyAsString(Constants.ENCODING);
			} catch (Exception exc) {
				throw new SocialAuthException("Failed to read response from  "
						+ ACCESS_TOKEN_URL);
			}
		}
		if (result == null || result.length() == 0) {
			throw new SocialAuthConfigurationException(
					"Problem in getting Access Token. Application key or Secret key may be wrong."
							+ "The server running the application should be same that was registered to get the keys.");
		}

		try {
			JSONObject jobj = new JSONObject(result);
			if (jobj.has("access_token")) {
				accessToken = jobj.getString("access_token");
			}
			if (accessToken != null) {
				isVerify = true;
				accessGrant = new AccessGrant();
				accessGrant.setKey(accessToken);
				if (scope != null) {
					accessGrant.setPermission(scope);
				} else {
					accessGrant.setPermission(Permission.DEFAULT);
				}
				accessGrant.setProviderId(getProviderId());
				LOG.debug("Obtaining user profile");
				return getProfile();
			} else {
				throw new SocialAuthException(
						"Access token and expires not found from "
								+ ACCESS_TOKEN_URL);
			}
		} catch (Exception e) {
			throw e;
		}
	}

	private Profile getProfile() throws Exception {
		LOG.debug("Obtaining user profile");
		Profile profile = new Profile();
		String u = PROFILE_URL + accessToken;
		Response serviceResponse;
		try {
			serviceResponse = HttpUtil.doHttpRequest(u,
					MethodType.GET.toString(), null, null);
		} catch (Exception e) {
			throw new SocialAuthException(
					"Failed to retrieve the user profile from  " + u, e);
		}
		String res;
		try {
			res = serviceResponse.getResponseBodyAsString(Constants.ENCODING);
		} catch (Exception exc) {
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
		profile.setProviderId(getProviderId());
		userProfile = profile;
		return profile;
	}

	/**
	 * Gets the list of contacts of the user.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         profile URL will be available
	 */

	@Override
	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		String url = CONTACTS_URL + accessToken;
		LOG.info("Fetching contacts from " + url);

		Response serviceResponse;
		try {
			serviceResponse = HttpUtil.doHttpRequest(url,
					MethodType.GET.toString(), null, null);
		} catch (Exception e) {
			throw new SocialAuthException("Error while getting contacts from "
					+ url);
		}
		if (serviceResponse.getStatus() != 200) {
			throw new SocialAuthException("Error while getting contacts from "
					+ url + "Status : " + serviceResponse.getStatus());
		}
		String respStr;
		try {
			respStr = serviceResponse
					.getResponseBodyAsString(Constants.ENCODING);
		} catch (Exception exc) {
			throw new SocialAuthException("Failed to read response from  "
					+ url);
		}
		LOG.debug("User Contacts list in JSON " + respStr);
		JSONObject resp = new JSONObject(respStr);
		List<Contact> plist = new ArrayList<Contact>();
		JSONArray items = new JSONArray();
		if (resp.has("response")) {
			JSONObject robj = resp.getJSONObject("response");
			if (robj.has("friends")) {
				JSONObject fobj = robj.getJSONObject("friends");
				if (fobj.has("items")) {
					items = fobj.getJSONArray("items");
				}
			} else {
				throw new SocialAuthException(
						"Failed to parse the user profile json : " + respStr);
			}
		} else {
			throw new SocialAuthException(
					"Failed to parse the user profile json : " + respStr);
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
				c.setId(obj.getString("id"));
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
	@Override
	public void updateStatus(final String msg) throws Exception {
		LOG.warn("WARNING: Not implemented for FourSquare");
		throw new SocialAuthException(
				"Update Status is not implemented for FourSquare");
	}

	/**
	 * Logout
	 */
	@Override
	public void logout() {
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

	/**
	 * Makes HTTP request to a given URL. It attaches access token in URL.
	 * 
	 * @param url
	 *            URL to make HTTP request.
	 * @param methodType
	 *            Method type can be GET, POST or PUT
	 * @param params
	 *            Not in use for FourSquare api function. You can pass required
	 *            parameter in query string.
	 * @param headerParams
	 *            Parameters need to pass as Header Parameters
	 * @param body
	 *            Request Body
	 * @return Response object
	 * @throws Exception
	 */
	@Override
	public Response api(final String url, final String methodType,
			final Map<String, String> params,
			final Map<String, String> headerParams, final String body)
			throws Exception {
		Response response = null;
		if (!isVerify) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		char separator = url.indexOf('?') == -1 ? '?' : '&';
		String urlStr = url + separator + "oauth_token=" + accessToken;
		LOG.debug("Calling URL : " + urlStr);
		if (MethodType.GET.toString().equals(methodType)) {
			try {
				response = HttpUtil.doHttpRequest(urlStr,
						MethodType.GET.toString(), null, headerParams);
			} catch (Exception e) {
				throw new SocialAuthException(
						"Error while making request to URL : " + urlStr, e);
			}
		} else if (MethodType.PUT.toString().equals(methodType)
				|| MethodType.POST.toString().equals(methodType)) {
			try {
				response = HttpUtil.doHttpRequest(urlStr, methodType, body,
						headerParams);
			} catch (Exception e) {
				throw new SocialAuthException(
						"Error while making request to URL : " + urlStr, e);
			}

		}
		return response;
	}

	/**
	 * Retrieves the user profile.
	 * 
	 * @return Profile object containing the profile information.
	 */
	@Override
	public Profile getUserProfile() throws Exception {
		if (userProfile == null && accessToken != null) {
			getProfile();
		}
		return userProfile;
	}

	@Override
	public AccessGrant getAccessGrant() {
		return accessGrant;
	}

	@Override
	public String getProviderId() {
		return config.getId();
	}

}
