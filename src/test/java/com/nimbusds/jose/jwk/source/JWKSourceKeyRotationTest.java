package com.nimbusds.jose.jwk.source;

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


import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;


/**
 * Tests key rotation with many threads. 
 */
public class JWKSourceKeyRotationTest {
	
	private static final Logger LOGGER = Logger.getLogger(JWKSourceKeyRotationTest.class.getName() );
	
	private static final class JWKReaderThread extends Thread {
		
		private final JWKSource<?> provider;
		
		// simulate the auth server issuing new tokens
		private final KeyIDSupplier keyIDSupplier;
		
		private boolean close;
		private int counter = 0;
		private boolean failed = false;
		
		public JWKReaderThread(JWKSource<?> provider, KeyIDSupplier keyIDSupplier) {
			super();
			this.provider = provider;
			this.keyIDSupplier = keyIDSupplier;
		}
		
		public void run() {
			String keyId = null;
			try {
				while(!close) {
					// get the latest key, i.e. this key would have been
					// used when a new token is created by the server
					keyId = keyIDSupplier.getKeyID();
					
					JWKMatcher matcher = new JWKMatcher.Builder().keyID(keyId).build();
					
					List<JWK> jwk = provider.get(new JWKSelector(matcher), null);
					
					if(jwk == null || jwk.isEmpty()) {
						throw new RuntimeException();
					}
					Thread.yield();
					
					counter++;
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, "Wanted key " + keyId + ", got exception", e);
				
				failed = true;
			}
		}
		
		public boolean isFailed() {
			return failed;
		}
		
		public int getCounter() {
			return counter;
		}
		
		public void close() {
			close = true;
		}
	}
	
	/**
	 * Verify there are no deadlocks and that
	 * all threads see the right key and that a single get of keys is sufficient.
	 */
	
	@Test
	public void testMultiThreadedKeyRotation() throws Exception {
		int numberOfRotations = 10;
		int threads = 200;
		long keyTimeToLive = 2000;
		long outdatedKeyTimeToLive = 500;
		long requestDelay = 100;  // simulate HTTPS request delay
		
		DelayedJWKSetSource<?> delayedSource = new DelayedJWKSetSource<>(requestDelay);
		
		RotationJWKSetSource<?> rotationJWKSetSource = new RotationJWKSetSource<>(numberOfRotations, keyTimeToLive, outdatedKeyTimeToLive, delayedSource);
		
		// default source adjusted for increased rate
		JWKSource<?> source = JWKSourceBuilder
			.create(rotationJWKSetSource)
			.rateLimited(keyTimeToLive - outdatedKeyTimeToLive - 1)
			.build();
		
		List<JWKReaderThread> runners = new ArrayList<>();
		for(int i = 0 ; i < threads; i++) {
			JWKReaderThread runner = new JWKReaderThread(source, rotationJWKSetSource);
			runners.add(runner);
		}
		
		try {
			for (JWKReaderThread jwkReaderThread : runners) {
				jwkReaderThread.start();
			}

			rotationJWKSetSource.start();
			
			LOGGER.info("Started " + threads + " reader threads");
			
			run(rotationJWKSetSource, runners);
		} finally {
			for(JWKReaderThread runner : runners) {
				runner.close();
			}
			rotationJWKSetSource.close();
			rotationJWKSetSource.join();
			
			for(JWKReaderThread runner : runners) {
				runner.join();
			}
		}
		
		// verify that all threads did get the right key all the time
		for(JWKReaderThread runner : runners) {
			assertFalse(runner.isFailed());
			assertTrue(runner.getCounter() > 0);
		}
		
		// verify that the underlying JWKSource was not invoked more than necessary
		assertEquals(rotationJWKSetSource.getJWKSetRetrievals(), numberOfRotations);
	}

	private void run(RotationJWKSetSource<?> rotationJWKSetSource, List<JWKReaderThread> runners) {
		// if one thread fails, stop all threads so that we can read the error message.

		// log stats on key change 
		String currentKeyId = null;
		while(rotationJWKSetSource.isAlive()) {
			boolean allThreadsAlive = true;
			for(JWKReaderThread runner : runners) {
				if (!runner.isAlive()) {
					allThreadsAlive = false;
				}
			}
			
			if(!allThreadsAlive) {
				break;
			}
			try {
				Thread.sleep(100);
				
				if(currentKeyId != rotationJWKSetSource.getKeyID()) {
					currentKeyId = rotationJWKSetSource.getKeyID();
					
					long count = 0;
					for(JWKReaderThread runner : runners) {
						count += runner.getCounter();
					}
					
					LOGGER.info("JWK set was fetched " + count + " times");
				}
			} catch (InterruptedException ignored) {
				// ignore
			}
		}
	}
}