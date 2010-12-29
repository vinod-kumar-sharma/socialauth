package org.brickred.socialauth.exception;

public class ProviderStateException extends ImplementationException {

	private static final String errorMessage = "This is not the same Provider object that was used for login.";
	private static final String resolution = "Please check if you stored the Provider in session";

	public ProviderStateException() {
		super();
	}

	@Override
	public String toString() {
		return errorMessage + resolution;
	}
}
