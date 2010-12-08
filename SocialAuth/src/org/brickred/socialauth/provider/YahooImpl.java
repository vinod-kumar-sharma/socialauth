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

import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.ServerDataException;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
import org.brickred.socialauth.util.XMLParseUtil;
import org.json.JSONArray;
import org.json.JSONObject;
import org.openid4java.consumer.ConsumerException;
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
import com.dyuproject.openid.OpenIdUser;
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
public class YahooImpl extends AbstractProvider implements AuthProvider
{
	private final Endpoint __yahoo;
	private OpenIdUser user;
	private Token token;
	private Consumer __consumer;

	public YahooImpl(final Properties props) throws ConsumerException {
		__yahoo = Endpoint.load(props, "api.login.yahoo.com");
		__consumer = Consumer.getInstance();
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	public String getLoginRedirectURL(final String returnTo) throws Exception {
		setProviderState(true);

		token = new Token(__yahoo.getConsumerKey());

		UrlEncodedParameterMap params = new UrlEncodedParameterMap().add(
				Constants.OAUTH_CALLBACK, returnTo);
		Response r;
		try {
			r = __consumer.fetchToken(__yahoo, params,
					TokenExchange.REQUEST_TOKEN, token);
		} catch (Exception e) {
			throw e;
		}
		if (r.getStatus() == 200 && token.getState() == Token.UNAUTHORIZED) {
			// unauthorized request token
			StringBuilder urlBuffer = Transport.buildAuthUrl(__yahoo
					.getAuthorizationUrl(), token, returnTo);
			return urlBuffer.toString();
		} else {
			throw new SocialAuthConfigurationException();
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
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		try {
			String verifier = request.getParameter(Constants.OAUTH_VERIFIER);
			if (token.authorize(request.getParameter(Constants.OAUTH_TOKEN),
					verifier)) {
				UrlEncodedParameterMap params = new UrlEncodedParameterMap();

				Response r = __consumer.fetchToken(__yahoo, params,
						TokenExchange.ACCESS_TOKEN, token);
				return getUserProfile();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private Profile getUserProfile() {
		Profile profile = new Profile();
		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				"http://social.yahooapis.com/v1/user/"
				+ token.getAttribute("xoauth_yahoo_guid")
				+ "/profile?format=json");
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __yahoo.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __yahoo,
						token, nts, sig));

		try {
			Response serviceResponse = connector.doGET(serviceParams
					.toStringRFC3986(), authorizationHeader);
			StringBuffer sb = new StringBuffer();
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					serviceResponse.getInputStream(), "UTF-8"));
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			System.out.println("-----------JSON---------" + sb.toString());
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
			e.printStackTrace();
		}
		return null;
	}


	/**
	 * Gets the list of contacts of the user and their email.
	 * @return List of profile objects representing Contacts. Only name and email
	 * will be available
	 */

	public List<Profile> getContactList() throws Exception {

		UrlEncodedParameterMap serviceParams = new UrlEncodedParameterMap(
				"http://social.yahooapis.com/v1/user/"
				+ token.getAttribute("xoauth_yahoo_guid") + "/contacts;count=max");
		NonceAndTimestamp nts = SimpleNonceAndTimestamp.getDefault();
		Signature sig = __yahoo.getSignature();

		HttpConnector connector = SimpleHttpConnector.getDefault();

		Parameter authorizationHeader = new Parameter("Authorization",
				HttpAuthTransport.getAuthHeaderValue(serviceParams, __yahoo,
						token, nts, sig));

		List<Profile> plist = new ArrayList<Profile>();
		Response serviceResponse;
		Element root;
		try {
			serviceResponse = connector.doGET(serviceParams
					.toStringRFC3986(), authorizationHeader);
		} catch (IOException ie) {
			throw ie;
		}
		try {
			root = XMLParseUtil.loadXmlResource(serviceResponse
					.getInputStream());
		} catch (Exception e) {
			throw new ServerDataException("Unable to retrieve the contacts.", e);
		}
		NodeList contactsList = root.getElementsByTagName("contact");
		if (contactsList != null && contactsList.getLength() > 0) {
			for (int i = 0; i < contactsList.getLength(); i++) {
				Element contact = (Element) contactsList.item(i);
				NodeList fieldList = contact.getElementsByTagName("fields");
				if (fieldList != null && fieldList.getLength() > 0) {
					String fname = "";
					String lname = "";
					String dispName = "";
					String address = "";
					for (int j = 0; j < fieldList.getLength(); j++) {
						Element field = (Element) fieldList.item(j);
						String type = XMLParseUtil.getElementData(field,
						"type");

						if ("email".equalsIgnoreCase(type)) {
							address = XMLParseUtil.getElementData(field,
							"value");
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
						Profile p = new Profile();
						p.setFirstName(fname);
						p.setLastName(lname);
						p.setEmail(address);
						p.setDisplayName(dispName);
						plist.add(p);
					}
				}
			}
		}
		return plist;
	}

	/**
	 * Updates the status on the chosen provider if available. This is not
	 * implemented for yahoo currently
	 * @param msg Message to be shown as user's status
	 */

	public void updateStatus(final String msg) {
		System.out.println("WARNING: Not implemented");
	}

	/**
	 * Logout
	 */
	public void logout() {
		token = null;
	}
}
