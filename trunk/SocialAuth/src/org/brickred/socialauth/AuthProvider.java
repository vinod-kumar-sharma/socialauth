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

import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * This is the main interface representing an authentication provider. First we
 * call the getLoginRedirectURL method to get the URL where the user needs to be
 * redirected. It is the responsibility of the caller to redirect the user to
 * that URL.
 * 
 * Once the external provider like Facebook redirects the user back to our
 * application, we call the verifyResponse method and pass along the HttpRequest
 * object that is called upon redirection.
 * 
 * If the verifyResponse method returns a non null profile object, we can start
 * calling the other methods to obtain user information, update status or import
 * contacts
 * 
 * @author Abhinav Maheshwari
 * 
 */

public interface AuthProvider {

	String EXT_NAMESPACE = "http://specs.openid.net/extensions/oauth/1.0";
	String EMAIL = "email";
	String COUNTRY = "country";
	String LANGUAGE = "language";
	String FULL_NAME = "fullname";
	String NICK_NAME = "nickname";
	String DOB = "dob";
	String GENDER = "gender";
	String POSTCODE = "postcode";
	String FIRST_NAME = "firstname";
	String LAST_NAME = "lastname";

	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 * @throws Exception
	 */
	public String getLoginRedirectURL(String redirectUri) throws Exception;

	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * @return Profile object containing the profile information
	 * @param request
	 *            Request object the request is received from the provider
	 * @throws Exception
	 */

	public Profile verifyResponse(HttpServletRequest request) throws Exception;

	/**
	 * Updates the status on the chosen provider if available. This may not be
	 * implemented for all providers.
	 * 
	 * @param msg
	 *            Message to be shown as user's status
	 */
	public void updateStatus(String msg) throws Exception;

	/**
	 * Gets the list of contacts of the user and their email. this may not be
	 * available for all providers.
	 * 
	 * @return List of profile objects representing Contacts. Only name and
	 *         email will be available
	 */
	public List<Contact> getContactList() throws Exception;

	/**
	 * Logout
	 */
	public void logout();

	/**
	 * 
	 * @param p
	 *            Permission object which can be Permission.AUHTHENTICATE_ONLY,
	 *            Permission.ALL, Permission.DEFAULT
	 */
	public void setPermission(final Permission p);
}
