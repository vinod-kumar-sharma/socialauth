package de.deltatree.social.web.filter.api.security;

import java.util.List;

import org.brickred.socialauth.SocialAuthManager;



public interface SASFSocialAuthManager {

	SocialAuthManager getSocialAuthManager() throws SASFSecurityException;

	List<String> getSocialAuthProviderIds() throws SASFSecurityException;

}
