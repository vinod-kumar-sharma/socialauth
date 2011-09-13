package de.deltatree.social.web.filter.impl;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import javax.servlet.http.HttpServletRequest;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.SocialAuthManager;

import de.deltatree.social.web.filter.api.SASFHelper;
import de.deltatree.social.web.filter.api.security.SASFSecurityException;
import de.deltatree.social.web.filter.api.security.SASFSocialAuthManager;
import de.deltatree.social.web.filter.impl.props.SASFProperties;

public class DefaultSASFHelper implements SASFHelper {
	private final static String SESSION_KEY = "S_SASFHelper";
	private final static String SESSION_SOCIAL_AUTH_PROVIDER = "SESSION_SOCIAL_AUTH_PROVIDER";
	private final static String SESSION_SOCIAL_AUTH_MANAGER = "SESSION_SOCIAL_AUTH_MANAGER";
	private final static String SESSION_ERROR = "S_SASFError";
	private final static String SESSION_ERROR_CAUSE = "S_SASFErrorCause";
	private final SASFSocialAuthManager sdbSocialAuthManager;
	private final HttpServletRequest request;
	private final SASFProperties props;

	public DefaultSASFHelper(HttpServletRequest req, SASFProperties props,
			SASFSocialAuthManager sdbSocialAuthManager)
			throws SASFSecurityException {
		this.request = req;
		this.props = props;
		this.sdbSocialAuthManager = sdbSocialAuthManager;
		setSessionKey();
	}

	private void setSessionKey() {
		this.request.getSession().setAttribute(SESSION_KEY, this);
	}

	@Override
	public SASFSocialAuthManager getMgr() {
		return sdbSocialAuthManager;
	}

	@Override
	public void setError(String message, Throwable cause) {
		this.request.getSession().setAttribute(SESSION_ERROR, message);
		this.request.getSession().setAttribute(SESSION_ERROR_CAUSE, cause);
	}

	@Override
	public String getError() {
		return (String) this.request.getSession().getAttribute(SESSION_ERROR);
	}

	@Override
	public Throwable getErrorCause() {
		return (Throwable) this.request.getSession().getAttribute(
				SESSION_ERROR_CAUSE);
	}

	@Override
	public String getErrorCauseAsString() {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Throwable errorCause = getErrorCause();
		if (errorCause != null)
			errorCause.printStackTrace(new PrintStream(bos));
		return bos.toString();
	}

	@Override
	public void setProvider(AuthProvider provider) {
		this.request.getSession().setAttribute(
				DefaultSASFHelper.SESSION_SOCIAL_AUTH_PROVIDER, provider);
	}

	@Override
	public AuthProvider getProvider() {
		return (AuthProvider) this.request.getSession().getAttribute(
				DefaultSASFHelper.SESSION_SOCIAL_AUTH_PROVIDER);
	}

	public void setAuthManager(SocialAuthManager socialAuthManager) {
		this.request.getSession().setAttribute(
				DefaultSASFHelper.SESSION_SOCIAL_AUTH_MANAGER,
				socialAuthManager);
	}

	@Override
	public SocialAuthManager getAuthManager() {
		return (SocialAuthManager) this.request.getSession().getAttribute(
				DefaultSASFHelper.SESSION_SOCIAL_AUTH_MANAGER);
	}

	@Override
	public String getServletMain() {
		return this.request.getContextPath() + props.getServletMain();
	}

	@Override
	public String getServletSuccess() {
		return this.request.getContextPath() + props.getServletMainSuccess();
	}

	@Override
	public String getOpenidReturnUrl() {
		String returnUrl = getURLWithContextPath()
				+ this.props.getOpenidReturnUrl();
		return returnUrl;
	}

	private String getURLWithContextPath() {
		StringBuffer sb = new StringBuffer();
		String protocol = request.getScheme();
		String host = request.getServerName();
		int port = request.getServerPort();
		String context = request.getContextPath();
		sb.append(protocol);
		sb.append("://");
		sb.append(host);
		if (port > 0) {
			if (!(protocol.equals("http") && port == 80)
					&& !(protocol.equals("https") && port == 443)) {
				sb.append(":");
				sb.append(port);
			}
		}
		sb.append(context);
		return sb.toString();

	}

	@Override
	public String getWebappSuccessAction() {
		return this.request.getContextPath() + props.webappSuccessAction();
	}

	@Override
	public String getServletLogoff() {
		return this.request.getContextPath() + props.getServletMainLogoff();
	}

	@Override
	public String getErrorPage() {
		return this.request.getContextPath() + props.getErrorPage();
	}

	public SASFProperties getProps() {
		return props;
	}
}
