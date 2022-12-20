package com.nimbusds.jose.jwk.source;


import java.io.IOException;
import java.util.Objects;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Test helper. 
 */

public class MutableJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	private volatile JWKSet jwkSet;

	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context) throws KeySourceException {
		return jwkSet;
	}

	public void setJwkSet(final JWKSet jwkSet) {
		Objects.requireNonNull(jwkSet);
		this.jwkSet = jwkSet;
	}
}
