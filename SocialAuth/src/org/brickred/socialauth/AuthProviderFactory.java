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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.brickred.socialauth.exception.SocialAuthConfigurationException;
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
	private static String propFileName = "oauth_consumer.properties";
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
		AuthProvider provider = getProvider(id, propFileName,
				AuthProvider.ALL_PERMISSIONS);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be google, yahoo,
	 *            hotmail, twitter, facebook.
	 * @param propertiesFileName
	 *            file name to read the properties
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id,
			final String propertiesFileName) throws Exception {
		AuthProvider provider = getProvider(id, propertiesFileName,
				AuthProvider.ALL_PERMISSIONS);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be google, yahoo,
	 *            hotmail, twitter, facebook.
	 * @param scope
	 *            scope is a permission setting. It can be
	 *            AuthProvider.AUTHENTICATION_ONLY or
	 *            AuthProvider.ALL_PERMISSIONS
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id, final int scope)
	throws Exception {
		AuthProvider provider = getProvider(id, propFileName, scope);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be google, yahoo,
	 *            hotmail, twitter, facebook.
	 * @param scope
	 *            scope is a permission setting. It can be
	 *            AuthProvider.AUTHENTICATION_ONLY or
	 *            AuthProvider.ALL_PERMISSIONS
	 * @param propertiesFileName
	 *            file name to read the properties
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id,
			final String propertiesFileName, final int scope) throws Exception {
		AuthProvider provider = getProvider(id, propertiesFileName, scope);
		return provider;

	}

	private static AuthProvider getProvider(final String id,
			final String fileName, final int scope) throws Exception {
		Properties props = new Properties();
		AuthProvider provider;
		try {
			InputStream in = AuthProviderFactory.class.getClassLoader()
			.getResourceAsStream(fileName);
			props.load(in);
			props.setProperty("id", id);
			if (facebook.equals(id)) {
				provider = new FacebookImpl(props, scope);
			} else if (twitter.equals(id)) {
				provider = new TwitterImpl(props, scope);
			} else if (aol.equals(id)) {
				provider = new AolImpl(props);
			} else if (google.equals(id)) {
				provider = new GoogleImpl(props, scope);
			} else if (yahoo.equals(id)) {
				provider = new YahooImpl(props, scope);
			} else if (hotmail.equals(id)) {
				provider = new HotmailImpl(props, scope);
			} else {
				provider = new OpenIdImpl(props);
			}
		} catch (NullPointerException ne) {
			throw new FileNotFoundException(fileName
					+ " file is not found in your class path");
		} catch (IOException ie) {
			throw new IOException(
			"Problem in loading the properties from oauth_consumer.properties file");
		} catch (SocialAuthConfigurationException se) {
			throw se;
		}
		return provider;
	}

}
