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

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.ProviderStateException;

import twitter4j.IDs;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.User;
import twitter4j.http.RequestToken;

import com.dyuproject.oauth.Endpoint;

/**
 * Twitter implementation of the provider. This is completely based on the
 * twitter4j library.
 * 
 * @author abhinavm@brickred.com
 * 
 */

public class TwitterImpl extends AbstractProvider implements AuthProvider {

	private final Endpoint __twitter;

	private Twitter twitter;
	private RequestToken requestToken;

	public TwitterImpl(final Properties props) {
		__twitter = Endpoint.load(props, "twitter.com");
		TwitterFactory factory = new TwitterFactory();
		twitter = factory.getInstance();
		String consumer_key = __twitter.getConsumerKey();
		String consumer_secret = __twitter.getConsumerSecret();
		twitter.setOAuthConsumer(consumer_key, consumer_secret);
	}

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */

	public String getLoginRedirectURL(final String redirect_uri) {
		setProviderState(true);
		try {
			requestToken = twitter.getOAuthRequestToken(redirect_uri);
			return requestToken.getAuthenticationURL();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
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
		if (!isProviderState()) {
			throw new ProviderStateException();
		}
		String verifier = request.getParameter("oauth_verifier");
		try {
			twitter.getOAuthAccessToken(requestToken, verifier);
			Profile p = new Profile();
			p.setValidatedId(String.valueOf(twitter.getId()));
			p.setDisplayName(twitter.getScreenName());
			User twitterUser = twitter.showUser(p.getDisplayName());
			p.setFullName(twitterUser.getName());
			p.setLocation(twitterUser.getLocation());
			p.setLanguage(twitterUser.getLang());
			p.setProfileImageURL(twitterUser.getProfileImageURL().toString());
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
	 */

	public void updateStatus(final String msg) {
		try {
			twitter.updateStatus(msg);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Gets the list of followers of the user and their email. this will be
	 * implemented later
	 * 
	 * @return null
	 */

	public List<Profile> getContactList() throws Exception {
		IDs ids = twitter.getFriendsIDs();
		int idsarr[] = ids.getIDs();
		int flength = idsarr.length;
		List<Profile> plist = new ArrayList<Profile>();
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
				Profile p = new Profile();
				p.setFirstName(u.getName());
				p.setEmail(u.getScreenName());
				plist.add(p);
			}
		}
		return plist;
	}

	/**
	 * Logout
	 */
	public void logout() {
		twitter = null;
	}

}