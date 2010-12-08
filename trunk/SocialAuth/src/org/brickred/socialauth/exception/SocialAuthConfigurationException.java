package org.brickred.socialauth.exception;

public class SocialAuthConfigurationException extends Exception {

	public SocialAuthConfigurationException() {
		super();
	}

	/**
	 * @param message
	 */
	public SocialAuthConfigurationException(final String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public SocialAuthConfigurationException(final Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public SocialAuthConfigurationException(final String message,
			final Throwable cause) {
		super(message, cause);
	}
}
