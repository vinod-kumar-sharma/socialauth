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
package org.brickred.socialauth.util;

import java.io.Serializable;
import java.util.Properties;

/**
 * It contains the configuration of application like consumer key and consumer
 * secret
 * 
 * @author tarunn@brickred.com
 * 
 */
public class OAuthConfig implements Serializable {

	private static final long serialVersionUID = 7574560869168900919L;
	private final String _consumerKey;
	private final String _consumerSecret;
	private final String _signatureMethod;
	private final String _transportName;

	/**
	 * It loads the configuration information from given properties for the
	 * given domain
	 * 
	 * @param props
	 *            Properties which contains the information of application
	 *            property file.
	 * @param domain
	 *            Domain for which configuration needs to be loaded.
	 * @return
	 */
	public static OAuthConfig load(final Properties props, final String domain) {
		String consumerKey = props.getProperty(domain + ".consumer_key");
		if (consumerKey == null) {
			throw new IllegalStateException(domain + ".consumer_key not found.");
		}

		String consumerSecret = props.getProperty(domain + ".consumer_secret");
		if (consumerSecret == null) {
			throw new IllegalStateException(domain
					+ ".consumer_secret not found.");
		}

		// optional
		String signatureMethod = props
				.getProperty(domain + ".signature_method");

		String transportName = props.getProperty(domain + ".transport_name");

		return new OAuthConfig(consumerKey, consumerSecret, signatureMethod,
				transportName);
	}

	/**
	 * 
	 * @param consumerKey
	 *            Application consumer key
	 * @param consumerSecret
	 *            Application consumer secret
	 * @param signatureMethod
	 *            Signature Method type
	 * @param transportName
	 *            Transport name
	 */
	public OAuthConfig(final String consumerKey, final String consumerSecret,
			final String signatureMethod, final String transportName) {
		_consumerKey = consumerKey;
		_consumerSecret = consumerSecret;
		if (signatureMethod == null || signatureMethod.length() == 0) {
			_signatureMethod = Constants.HMACSHA1_SIGNATURE;
		} else {
			_signatureMethod = signatureMethod;
		}
		if (transportName == null || transportName.length() == 0) {
			_transportName = MethodType.GET.toString();
		} else {
			_transportName = transportName;
		}
	}

	/**
	 * Retrieves the consumer key
	 * 
	 * @return the consumer key
	 */
	public String get_consumerKey() {
		return _consumerKey;
	}

	/**
	 * Retrieves the consumer secret
	 * 
	 * @return the consumer secret
	 */
	public String get_consumerSecret() {
		return _consumerSecret;
	}

	/**
	 * Retrieves the signature method
	 * 
	 * @return the signature method
	 */
	public String get_signatureMethod() {
		return _signatureMethod;
	}

	/**
	 * Retrieves the transport name
	 * 
	 * @return the transport name
	 */
	public String get_transportName() {
		return _transportName;
	}

}
