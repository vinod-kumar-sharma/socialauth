package org.brickred.socialauth;

public class AbstractProvider {
	private boolean providerState;

	public boolean isProviderState() {
		return providerState;
	}

	protected void setProviderState(final boolean providerState) {
		this.providerState = providerState;
	}
}
