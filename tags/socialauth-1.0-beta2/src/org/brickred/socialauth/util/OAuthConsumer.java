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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.brickred.socialauth.exception.SocialAuthException;

public class OAuthConsumer {

	private String consumerKey;
	private String consumerSecret;
	private String accessToken;
	private String tokenSecret;
	public static String HMACSHA1_SIGNATURE = "HMAC-SHA1";
	public OAuthConsumer() {
	}
	public OAuthConsumer(String consumerKey, String consumerSecret,
			String accessToken, String tokenSecret) {
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
		this.accessToken = accessToken;
		this.tokenSecret = tokenSecret;
	}

	/**
	 * Encode the string for OAuth
	 * 
	 * @param value
	 * @return
	 * @throws Exception
	 */
	public String encode(String value) throws Exception {
		if (value == null) {
			return "";
		}

		try {
			return URLEncoder.encode(value, "utf-8")
			// OAuth encodes some characters differently:
			.replace("+", "%20").replace("*", "%2A")
			.replace("%7E", "~");
			// This could be done faster with more hand-crafted code.
		} catch (UnsupportedEncodingException wow) {
			throw new SocialAuthException(wow.getMessage(), wow);
		}
	}

	/**
	 * It returns a signature to make OAuth request.
	 * 
	 * @param signatureType
	 *            Type of signature. It can be HMAC-SHA1.
	 * @param method
	 *            Method type can be GET, POST or PUT
	 * @param url
	 * @param args
	 * @return String the signature
	 * @throws Exception
	 */
	public String generateSignature(String signatureType, String method,
			String url, Map<String, String> args) throws Exception {
		if (HMACSHA1_SIGNATURE.equals(signatureType)) {
			return getHMACSHA1(method, url, args);
		} else {
			throw new SocialAuthException(
			"Signature type is null or not a valid signature type");
		}
	}

	private String getHMACSHA1(String method, String url,
			Map<String, String> args) throws Exception {

		if (consumerSecret == null || consumerSecret.length() == 0) {
			throw new SocialAuthException("Consumer secret is null");
		}
		if (tokenSecret == null || tokenSecret.length() == 0) {
			throw new SocialAuthException("Token secret is null");
		}
		if (method == null || method.length() == 0) {
			throw new SocialAuthException("method is null");
		}
		if (url == null || url.length() == 0) {
			throw new SocialAuthException("URL is null");
		}
		String key = consumerSecret + "&" + tokenSecret;
		try {
			// get an hmac_sha1 key from the raw key bytes
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("UTF-8"),
			"HMAC-SHA1");

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(signingKey);

			String data = encode(method) + "&" + encode(url) + "&"
			+ encode(buildParams(args));
			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(data.getBytes("UTF-8"));

			// base64-encode the hmac
			return Base64.encodeBytes(rawHmac);
		} catch (Exception e) {
			throw new SocialAuthException("Unable to generate HMAC-SHA1", e);
		}
	}

	/**
	 * 
	 * @param args
	 * @return String
	 * @throws Exception
	 */
	public String buildParams(Map<String, String> args) throws Exception {
		List<String> argList = new ArrayList<String>();
		for (String key : args.keySet()) {
			String arg = key + "=" + encode(args.get(key));
			argList.add(arg);
		}
		Collections.sort(argList);
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < argList.size(); i++) {
			s.append(argList.get(i));
			if (i != argList.size() - 1) {
				s.append("&");
			}
		}

		return s.toString();
	}

	/**
	 * Retrieves the Consumer Key
	 * 
	 * @return String the consumer key
	 */
	public String getConsumerKey() {
		return consumerKey;
	}

	/**
	 * Updates the consumer key
	 * 
	 * @param consumerKey
	 *            the consumer key
	 */
	public void setConsumerKey(String consumerKey) {
		this.consumerKey = consumerKey;
	}

	/**
	 * Retrieves the consumer secret
	 * 
	 * @return String the consumer secret
	 */
	public String getConsumerSecret() {
		return consumerSecret;
	}

	/**
	 * Updats the consumer secret
	 * 
	 * @param consumerSecret
	 *            the consumer secret.
	 */
	public void setConsumerSecret(String consumerSecret) {
		this.consumerSecret = consumerSecret;
	}

	/**
	 * Retrieves the access token
	 * 
	 * @return String the Access Token
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Updates the access token
	 * 
	 * @param accessToken
	 *            the access token
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Retrieves the token secret
	 * 
	 * @return String the token secret
	 */
	public String getTokenSecret() {
		return tokenSecret;
	}

	/**
	 * Updates the token secret
	 * 
	 * @param tokenSecret
	 *            the token secret
	 */
	public void setTokenSecret(String tokenSecret) {
		this.tokenSecret = tokenSecret;
	}
}
