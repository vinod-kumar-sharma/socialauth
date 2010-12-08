package org.brickred.socialauth.exception;

public class ProviderStateException extends ImplementationException {

	private String errorMessage = "Provider object is not from session";
	public ProviderStateException() {
		super();
	}

	@Override
	public String toString() {
		return errorMessage;
	}
}
