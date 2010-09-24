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

package org.brickred.socialauth;

import java.io.InputStream;
import java.util.Properties;

import org.brickred.socialauth.provider.AolImpl;
import org.brickred.socialauth.provider.FacebookImpl;
import org.brickred.socialauth.provider.GoogleImpl;
import org.brickred.socialauth.provider.HotmailImpl;
import org.brickred.socialauth.provider.OpenIdImpl;
import org.brickred.socialauth.provider.TwitterImpl;
import org.brickred.socialauth.provider.YahooImpl;

/**
 * This is a factory which creates an instance of the requested provider based
 * on the string passed as id. Currently available providers are given as 
 * static constants. If requested provider id is not matched, it returns the
 * OpenId provider.
 * 
 * @author tarunn@brickred.com
 * 
 */
public class AuthProviderFactory {

	public static String facebook = "facebook";
	public static String twitter = "twitter";
	public static String google = "google";
	public static String yahoo = "yahoo";
	public static String hotmail = "hotmail";
	public static String aol = "aol";
		
	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be google, yahoo,
	 *            hotmail, twitter, facebook.
	 * 
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id)
	throws Exception {
		Properties props = new Properties();
		InputStream in = AuthProviderFactory.class.getClassLoader()
		.getResourceAsStream("oauth_consumer.properties");
		props.load(in);
		props.setProperty("id", id);
		if (facebook.equals(id)) {
			return new FacebookImpl(props);
		} else if (twitter.equals(id)) {
			return new TwitterImpl(props);
		} else if (aol.equals(id)) {
			return new AolImpl(props);
		} else if (google.equals(id)) {
			return new GoogleImpl(props);
		} else if (yahoo.equals(id)) {
			return new YahooImpl(props);
		} else if (hotmail.equals(id)) {
			return new HotmailImpl(props);
		} else {
			return new OpenIdImpl(props);
		}
	}

}
