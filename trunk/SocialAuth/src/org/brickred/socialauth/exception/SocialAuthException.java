package org.brickred.socialauth.exception;

public class SocialAuthException extends Exception {
	public SocialAuthException() {
		super();
	}

	/**
	 * @param message
	 */
	public SocialAuthException(final String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public SocialAuthException(final Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public SocialAuthException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
