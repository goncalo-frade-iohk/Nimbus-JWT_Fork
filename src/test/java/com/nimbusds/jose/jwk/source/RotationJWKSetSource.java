/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Helper class for multi-threaded testing. Simulates a server which rotates
 * its keys by issuing keys with overlapping validity.
 */
public class RotationJWKSetSource<C extends SecurityContext> extends Thread implements JWKSetSource<C>, KeyIDSupplier {
	
	private static final Logger LOGGER = Logger.getLogger(RotationJWKSetSource.class.getName() );
	
	private final int iterations;
	private final long keyTimeToLive;
	private final long outdatedKeyTimeToLive;
	private final MutableJWKSetSource<C> delegate;
	private final AtomicInteger retrievalsCounter = new AtomicInteger();
	
	private boolean closed = false;
	
	// the latest key, which should be requested to the top level JWKSetSource.
	private volatile String latestKeyId;
	
	public RotationJWKSetSource(int iterations, long keyTimeToLive, long outdatedKeyTimeToLive, MutableJWKSetSource<C> delegate)
		throws JOSEException {
		
		this.iterations = iterations + 1;
		this.keyTimeToLive = keyTimeToLive;
		this.outdatedKeyTimeToLive = outdatedKeyTimeToLive;
		this.delegate = delegate;
		
		populateKeys(0, 1);
	}
	
	private void populateKeys(int offset, int length) throws JOSEException {
		
		List<JWK> keys = new ArrayList<>();
		for(int i = offset; i < offset + length; i++) {
			ECKey jwk = new ECKeyGenerator(Curve.P_256)
				.keyID(Integer.toString(i))
				.generate()
				.toPublicJWK();
			keys.add(jwk);
		}
		
		this.delegate.setJwkSet(new JWKSet(keys));
		
		this.latestKeyId = Integer.toString(offset + length - 1);
	}
	
	@Override
	public void close() throws IOException {
		this.closed = true;
		interrupt();
	}
	
	public void run() {
		try {
			for(int i = 0; i < iterations - 2 && !closed; i++) {
				Thread.sleep(keyTimeToLive - outdatedKeyTimeToLive);
				
				populateKeys(i, 2);
				LOGGER.info("New key " + (i + 1) + ", now have " + getKeyIDs());
				Thread.sleep(outdatedKeyTimeToLive);
				
				populateKeys(i + 1, 1);
				LOGGER.info("Retiring old key " + i + ", now have " + getKeyIDs());
			}
		} catch(InterruptedException e) {
			Thread.interrupted();
			// do nothing
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private List<String> getKeyIDs() throws KeySourceException {
		List<String> ids = new ArrayList<>();
		JWKSet jwkSet = delegate.getJWKSet(null, iterations, null);
		for (JWK jwk : jwkSet.getKeys()) {
			ids.add(jwk.getKeyID());
		}
		return ids;
	}
	
	@Override
	public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, C context)
		throws KeySourceException {
		retrievalsCounter.incrementAndGet();
		return delegate.getJWKSet(refreshEvaluator, currentTime, context);
	}
	
	public String getLatestKeyId() {
		return latestKeyId;
	}
	
	@Override
	public String getKeyID() {
		return getLatestKeyId();
	}
	
	public int getJWKSetRetrievals() {
		return retrievalsCounter.get();
	}
}