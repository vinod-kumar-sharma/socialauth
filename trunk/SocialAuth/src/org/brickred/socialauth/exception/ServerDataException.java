package org.brickred.socialauth.exception;

public class ServerDataException extends Exception {

	public ServerDataException() {
		super();
	}

	/**
	 * @param message
	 */
	public ServerDataException(final String message) {
		super(message);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public ServerDataException(final String message, final Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param cause
	 */
	public ServerDataException(final Throwable cause) {
		super(cause);
	}
}
