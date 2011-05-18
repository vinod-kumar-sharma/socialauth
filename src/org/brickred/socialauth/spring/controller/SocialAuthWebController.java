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
package org.brickred.socialauth.spring.controller;

import java.util.Properties;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.AuthProviderFactory;
import org.brickred.socialauth.spring.bean.SocialAuthTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Generic controller for managing socialauth-provider connection flow. This is
 * called when the user hits a URL of the following form
 * 
 * /socialauth{pattern}?id={providerId}
 * 
 * where pattern depends on your configuration, for example .do and the
 * providerId may be one of facebook,foursquare, google,
 * hotmail,linkedin,myspace, openid, twitter, yahoo
 * 
 * The connect method is called when the user hits the above URL and it
 * redirects to the actual provider for login. Once the user provides
 * credentials and the provider redirects back to your application, one of the
 * callback methods is called
 */
@Controller
@RequestMapping("/socialauth")
public class SocialAuthWebController {

	private String baseCallbackUrl;
	private String successPageURL;
	private Properties properites;
	@Autowired
	private SocialAuthTemplate socialAuthTemplate;

	/**
	 * Constructs a SocialAuthWebController.
	 * 
	 * @param applicationUrl
	 *            the base URL for this application (with context e.g
	 *            http://opensource.brickred.com/socialauthdemo, used to
	 *            construct the callback URL passed to the providers
	 * @param successPageURL
	 *            the URL of success page or controller, where you want to
	 *            access sign in user details like profile, contacts etc.
	 * @param socialAuthProperties
	 *            properties containing key/secret for different providers and
	 *            information of custom provider. e.g
	 *            www.google.com.consumer_key = opensource.brickred.com <br/>
	 *            and for custom provider key/value pair will be <br/>
	 *            socialauth.myprovider =
	 *            org.brickred.socialauth.provider.MyProviderImpl <br/>
	 *            where myprovider will be {providerId} and value will be the
	 *            fully class name.
	 */
	@Inject
	public SocialAuthWebController(String applicationUrl,
			String successPageURL, Properties socialAuthProperties) {
		this.baseCallbackUrl = applicationUrl;
		this.successPageURL = successPageURL;
		this.properites = socialAuthProperties;
	}

	/**
	 * Initiates the connection with required provider.It redirects the browser
	 * to an appropriate URL which will be used for authentication with the
	 * requested provider.
	 */
	@RequestMapping(params = "id")
	public String connect(@RequestParam("id") String providerId,
			HttpServletRequest request) throws Exception {
		AuthProvider provider = AuthProviderFactory.getInstance(providerId,
				properites);
		String url = provider.getLoginRedirectURL(baseCallbackUrl
				+ request.getServletPath());
		socialAuthTemplate.setProvider(provider);
		return "redirect:" + url;
	}

	@RequestMapping(params = "oauth_token")
	public String oauthCallback(HttpServletRequest request) {
		callback(request);
		return "redirect:/" + successPageURL;
	}

	@RequestMapping(params = "code")
	public String oauth2Callback(HttpServletRequest request) {
		callback(request);
		return "redirect:/" + successPageURL;
	}

	@RequestMapping(params = "wrap_verification_code")
	public String hotmailCallback(HttpServletRequest request) {
		callback(request);
		return "redirect:/" + successPageURL;
	}

	@RequestMapping(params = "openid.claimed_id")
	public String openidCallback(HttpServletRequest request) {
		callback(request);
		return "redirect:/" + successPageURL;
	}

	private void callback(HttpServletRequest request) {
		AuthProvider provider = socialAuthTemplate.getProvider();
		if (provider != null) {
			try {
				provider.verifyResponse(request);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
