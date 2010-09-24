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

import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.User;
import twitter4j.http.RequestToken;

import com.dyuproject.oauth.Endpoint;

/**
 * Twitter implementation of the provider. This is completely
 * based on the twitter4j library.
 * 
 * @author Abhinav Maheshwari
 * @author abhinavm@brickred.com
 *
 */

public class TwitterImpl implements AuthProvider {

	final Endpoint __twitter;

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

	public String getLoginRedirectURL(final String redirect_uri) {
		try {
			requestToken = twitter.getOAuthRequestToken(redirect_uri);
			return requestToken.getAuthenticationURL();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public Profile verifyResponse(final HttpServletRequest request)
	{
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
			return p;
		} catch (TwitterException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void updateStatus(final String msg) {
		try {
			twitter.updateStatus(msg);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public List<Profile> getContactList() {
		return null;
	}

}