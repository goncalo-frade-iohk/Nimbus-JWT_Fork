/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.nimbusds.jose.jwk.source;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Test helper. Counts the number of times the keys are returned.
 * 
 */
public class CountingJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	private final JWKSet jwkSet;
	private final AtomicLong counter = new AtomicLong();

	public CountingJWKSetSource(JWKSet jwkSet) {
		this.jwkSet = jwkSet;
	}
	
	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context) throws KeySourceException {
		counter.incrementAndGet();
		return jwkSet;
	}
	
	public long getCount() {
		return counter.get();
	}

}
