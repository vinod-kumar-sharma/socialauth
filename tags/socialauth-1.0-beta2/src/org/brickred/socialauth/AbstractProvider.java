package org.brickred.socialauth;

import java.io.Serializable;

public class AbstractProvider implements Serializable {
	private boolean providerState;

	public boolean isProviderState() {
		return providerState;
	}

	protected void setProviderState(final boolean providerState) {
		this.providerState = providerState;
	}
}
