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
import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.brickred.socialauth.exception.SocialAuthConfigurationException;
import org.brickred.socialauth.exception.SocialAuthException;

/**
 * This is a factory which creates an instance of the requested provider based
 * on the string passed as id. Currently available providers are facebook,
 * foursquare, google, hotmail, linkedin,myspace, openid, twitter, yahoo . If
 * requested provider id is not matched, it returns the OpenId provider.
 * 
 * @author tarunn@brickred.com
 * 
 */
public class AuthProviderFactory {

	private static String propFileName = "oauth_consumer.properties";
	private static Map<String, Class> providerMap;
	private static final Log LOG = LogFactory.getLog(AuthProviderFactory.class);

	static {
		providerMap = new HashMap<String, Class>();
		providerMap.put("facebook",
				org.brickred.socialauth.provider.FacebookImpl.class);
		providerMap.put("foursquare",
				org.brickred.socialauth.provider.FourSquareImpl.class);
		providerMap.put("google",
				org.brickred.socialauth.provider.GoogleImpl.class);
		providerMap.put("hotmail",
				org.brickred.socialauth.provider.HotmailImpl.class);
		providerMap.put("linkedin",
				org.brickred.socialauth.provider.LinkedInImpl.class);
		providerMap.put("myspace",
				org.brickred.socialauth.provider.MySpaceImpl.class);
		providerMap.put("openid",
				org.brickred.socialauth.provider.OpenIdImpl.class);
		providerMap.put("twitter",
				org.brickred.socialauth.provider.TwitterImpl.class);
		providerMap.put("yahoo",
				org.brickred.socialauth.provider.YahooImpl.class);

	}

	/**
	 * It provides the instance of requested provider
	 * 
	 * @param id
	 *            the id of requested provider. It can be facebook, foursquare,
	 *            google, hotmail, linkedin,myspace, twitter, yahoo
	 * 
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id) throws Exception {
		AuthProvider provider = getProvider(id, propFileName, null);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be facebook, foursquare,
	 *            google, hotmail, linkedin,myspace, twitter, yahoo.
	 * @param propertiesFileName
	 *            file name to read the properties
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id,
			final String propertiesFileName) throws Exception {
		AuthProvider provider = getProvider(id, propertiesFileName, null);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be facebook, foursquare,
	 *            google, hotmail, linkedin,myspace, twitter, yahoo.
	 * @param classLoader
	 *            classloader to load the properties
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id,
			final ClassLoader classLoader) throws Exception {
		AuthProvider provider = getProvider(id, propFileName, classLoader);
		return provider;

	}

	/**
	 * 
	 * @param id
	 *            the id of requested provider. It can be facebook, foursquare,
	 *            google, hotmail, linkedin,myspace, twitter, yahoo.
	 * @param propertiesFileName
	 *            file name to read the properties
	 * @param classLoader
	 *            classloader to load the properties
	 * @return AuthProvider the instance of requested provider based on given
	 *         id. If id is a URL it returns the OpenId provider.
	 * @throws Exception
	 */
	public static AuthProvider getInstance(final String id,
			final String propertiesFileName, final ClassLoader classLoader)
			throws Exception {
		AuthProvider provider = getProvider(id, propertiesFileName, classLoader);
		return provider;

	}

	private static AuthProvider getProvider(final String id,
			final String fileName, final ClassLoader classLoader)
			throws Exception {
		Properties props = new Properties();
		AuthProvider provider;
		ClassLoader loader = null;
		if (classLoader != null) {
			loader = classLoader;
		} else {
			loader = AuthProviderFactory.class.getClassLoader();
		}
		try {
			InputStream in = loader.getResourceAsStream(fileName);
			props.load(in);
			props.setProperty("id", id);
			for (Iterator iter = props.keySet().iterator(); iter.hasNext();) {
				String str = (String) iter.next();
				if (str.startsWith("socialauth.")) {
					String val = str.substring("socialauth.".length());
					registerProvider(val,
							Class.forName(props.get(str).toString()));
				}
			}
		} catch (NullPointerException ne) {
			throw new FileNotFoundException(fileName
					+ " file is not found in your class path");
		} catch (IOException ie) {
			throw new IOException("Could not load configuration from "
					+ fileName);
		}

		Class obj = providerMap.get(id);
		if (obj == null) {
			try {
				URL url = new URL(id);
				obj = providerMap.get("openid");
			} catch (MalformedURLException me) {
				throw new SocialAuthException(id
						+ " is not a provider or valid OpenId URL");
			}
		}

		try {
			Constructor cons = obj.getConstructor(Properties.class);
			provider = (AuthProvider) cons.newInstance(props);
		} catch (NoSuchMethodException me) {
			LOG.warn(obj.getName() + " does not implement a constructor "
					+ obj.getName() + "(Poperties props)");
			provider = (AuthProvider) obj.newInstance();
		} catch (Exception e) {
			throw new SocialAuthConfigurationException(e);
		}
		return provider;
	}

	/**
	 * It register a new provider in AuthProviderFactory.
	 * 
	 * @param pname
	 *            provider name
	 * @param clazz
	 *            class name of the provider implementation.
	 */
	public static void registerProvider(final String pname, final Class clazz) {
		providerMap.put(pname, clazz);
	}
}
