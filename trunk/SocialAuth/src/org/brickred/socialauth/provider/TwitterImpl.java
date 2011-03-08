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
import org.brickred.socialauth.exception.UserDeniedPermissionException;
import org.brickred.socialauth.util.OAuthConfig;

import twitter4j.IDs;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.User;
import twitter4j.http.RequestToken;

/**
 * Twitter implementation of the provider. This is completely based on the
 * twitter4j library.
 * 
 * @author abhinavm@brickred.com
 * 
 */

public class TwitterImpl extends AbstractProvider implements AuthProvider,
		Serializable {

	private static final long serialVersionUID = 1908393649053616794L;
	private static final String PROPERTY_DOMAIN = "twitter.com";
	private final Log LOG = LogFactory.getLog(TwitterImpl.class);

	private Twitter twitter;
	private RequestToken requestToken;
	private Permission scope;
	private Properties properties;
	private boolean isVerify;
	private OAuthConfig config;

	public TwitterImpl(final Properties props) throws Exception {
		try {
			this.properties = props;
			config = OAuthConfig.load(this.properties, PROPERTY_DOMAIN);
		} catch (IllegalStateException e) {
			throw new SocialAuthConfigurationException(e);
		}
		if (config.get_consumerSecret().length() == 0) {
			throw new SocialAuthConfigurationException(
					"twitter.com.consumer_secret value is null");
		}
		if (config.get_consumerKey().length() == 0) {
			throw new SocialAuthConfigurationException(
					"twitter.com.consumer_key value is null");
		}
		TwitterFactory factory = new TwitterFactory();
		twitter = factory.getInstance();

		twitter.setOAuthConsumer(config.get_consumerKey(),
				config.get_consumerSecret());
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	@Override
	public String getLoginRedirectURL(final String redirect_uri)
			throws Exception {
		LOG.info("Determining URL for redirection");
		setProviderState(true);
		try {
			requestToken = twitter.getOAuthRequestToken(redirect_uri);
			String url = requestToken.getAuthenticationURL();
			LOG.info("Redirection to following URL should happen : " + url);
			return url;
		} catch (Exception e) {
			throw new SocialAuthException(e);
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

	@Override
	public Profile verifyResponse(final HttpServletRequest request)
			throws Exception {
		LOG.info("Retrieving Access Token in verify response function");
		if (request.getParameter("denied") != null) {
			throw new UserDeniedPermissionException();
		}
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		String verifier = request.getParameter("oauth_verifier");
		try {
			twitter.getOAuthAccessToken(requestToken, verifier);
			isVerify = true;
			LOG.debug("Obtaining user profile");
			Profile p = new Profile();
			p.setValidatedId(String.valueOf(twitter.getId()));
			p.setDisplayName(twitter.getScreenName());
			User twitterUser = twitter.showUser(p.getDisplayName());
			p.setFullName(twitterUser.getName());
			p.setLocation(twitterUser.getLocation());
			p.setLanguage(twitterUser.getLang());
			p.setProfileImageURL(twitterUser.getProfileImageURL().toString());
			LOG.debug("User profile : " + p.toString());
			return p;
		} catch (TwitterException e) {
			throw e;
		}
	}

	/**
	 * Updates the status on Twitter.
	 * 
	 * @param msg
	 *            Message to be shown as user's status
	 * @throws Exception
	 */

	@Override
	public void updateStatus(final String msg) throws Exception {
		LOG.info("Updatting status " + msg);
		if (!isVerify) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		if (msg == null || msg.trim().length() == 0) {
			throw new ServerDataException("Status cannot be blank");
		}
		try {
			twitter.updateStatus(msg);
		} catch (Exception e) {
			throw new SocialAuthException(e);
		}
	}

	/**
	 * Gets the list of followers of the user and their screen name.
	 * 
	 * @return List of contact objects representing Contacts. Only name and
	 *         screen name will be available
	 */

	@Override
	public List<Contact> getContactList() throws Exception {
		if (!isVerify) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		LOG.info("Fetching user contacts");
		IDs ids = twitter.getFriendsIDs();
		int idsarr[] = ids.getIDs();
		int flength = idsarr.length;
		LOG.debug("Contacts found : " + flength);
		List<Contact> plist = new ArrayList<Contact>();
		if (flength > 0) {
			List<User> ulist = new ArrayList<User>();
			if (flength > 100) {
				int i = flength / 100;
				int temparr[];
				for (int j = 1; j <= i; j++) {
					temparr = new int[100];
					for (int k = (j - 1) * 100, c = 0; k < j * 100; k++, c++) {
						temparr[c] = idsarr[k];
					}
					ulist.addAll(twitter.lookupUsers(temparr));
				}
				if (flength > i * 100) {
					temparr = new int[flength - i * 100];
					for (int k = i * 100, c = 0; k < flength; k++, c++) {
						temparr[c] = idsarr[k];
					}
					ulist.addAll(twitter.lookupUsers(temparr));
				}
			} else {
				ulist.addAll(twitter.lookupUsers(idsarr));
			}
			for (User u : ulist) {
				Contact p = new Contact();
				p.setFirstName(u.getName());
				p.setProfileUrl("http://" + PROPERTY_DOMAIN + "/"
						+ u.getScreenName());
				plist.add(p);
			}
		}
		return plist;
	}

	/**
	 * Logout
	 */
	@Override
	public void logout() {
		twitter = null;
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

}