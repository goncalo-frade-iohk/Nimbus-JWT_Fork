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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;


/**
 * Test that requests for unknown keys are not affecting requests for known keys.
 * Unknown keys will result in a refresh of the keys, however the rate limit will take
 * effect and block most of the refreshes, protecting the downstream JWKs end-point against
 * a wave of requests.
 * 
 */
public class JWKSourceUnknownKeysTest {
	
	private static final Logger LOGGER = Logger.getLogger(JWKSourceUnknownKeysTest.class.getName() );
	
	private static abstract class AbstractKeyJWKReaderThread extends Thread {

		protected boolean close = false;
		protected final JWKSource<?> provider;
		protected final String keyId;
		protected int counter = 0;
		protected boolean failed = false;
		
		public AbstractKeyJWKReaderThread(JWKSource<?> provider, String keyId) {
			super();
			this.provider = provider;
			this.keyId = keyId;
		}
				
		public void close() {
			close = true;
		}
		
		public boolean isFailed() {
			return failed;
		}
		
		public int getCounter() {
			return counter;
		}		
	}

	
	private static final class KnownKeyJWKReaderThread extends AbstractKeyJWKReaderThread {
		
		public KnownKeyJWKReaderThread(JWKSource<?> provider, String keyId) {
			super(provider, keyId);
		}

		public void run() {
			try {
				while(!close) {
					// get a key id and expect there is a result
					JWKMatcher matcher = new JWKMatcher.Builder().keyID(keyId).build();
					
					List<JWK> jwk = provider.get(new JWKSelector(matcher), null);
					
					if(jwk == null || jwk.isEmpty()) {
						throw new RuntimeException();
					}
					Thread.yield();
					
					counter++;
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, "Wanted positive result for key " + keyId + ", got exception", e);
				
				failed = true;
			}
		}
	}
	
	private static final class UnknownKeyJWKReaderThread extends AbstractKeyJWKReaderThread {
		
		public UnknownKeyJWKReaderThread(JWKSource<?> provider, String keyId) {
			super(provider, keyId);
		}

		public void run() {
			try {
				while(!close) {
					// get a key id and expect there is no result
					JWKMatcher matcher = new JWKMatcher.Builder().keyID(keyId).build();

					try {
						List<JWK> jwk = provider.get(new JWKSelector(matcher), null);
					
						if(jwk != null && !jwk.isEmpty()) {
							throw new RuntimeException("Key not expected for unknown key id");
						}
						Thread.yield();
					} catch(RateLimitReachedException e) {
						// ignore
					}
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, "Wanted negative result for key " + keyId + ", got exception", e);
				
				failed = true;
			}
		}
	}
	
	@Test
	public void testMultiThreadedKnownAndUnknownKeys() throws Exception {
		String knownKeyId = "1234567890";
		String unknownKeyId = "abcdefghi";
		
		List<JWK> keys = new ArrayList<>();
		ECKey jwk = new ECKeyGenerator(Curve.P_256)
			.keyID(knownKeyId)
			.generate()
			.toPublicJWK();
		keys.add(jwk);
		
		JWKSet jwkSet = new JWKSet(keys);
		CountingJWKSetSource<?> jwkSetSource = new CountingJWKSetSource<>(jwkSet);
		
		int threads = 100;
		int keyTimeToLive = 2000;
		int iterations = 3;

		// the keys are the same always, but they will be refreshed because of the
		// requests for an unknown key
		
		JWKSource<?> source = JWKSourceBuilder
			.create(jwkSetSource)
			.rateLimited(keyTimeToLive)
			.build();
		
		List<KnownKeyJWKReaderThread> knownKeyThreads = new ArrayList<>();
		for(int i = 0 ; i < threads; i++) {
			KnownKeyJWKReaderThread runner = new KnownKeyJWKReaderThread(source, knownKeyId);
			knownKeyThreads.add(runner);
		}

		List<UnknownKeyJWKReaderThread> unknownKeyThreads = new ArrayList<>();
		for(int i = 0 ; i < threads; i++) {
			UnknownKeyJWKReaderThread runner = new UnknownKeyJWKReaderThread(source, unknownKeyId);
			unknownKeyThreads.add(runner);
		}

		List<AbstractKeyJWKReaderThread> allThreads = new ArrayList<>();
		allThreads.addAll(knownKeyThreads);
		allThreads.addAll(unknownKeyThreads);
		
		try {
			for(AbstractKeyJWKReaderThread thread : allThreads) {
				thread.start();
			}
			
			LOGGER.info("Started " + allThreads.size() + " reader threads");

			run(jwkSetSource, (iterations + 1) * 2, allThreads, keyTimeToLive * iterations * 2); 
		} finally {
			for(AbstractKeyJWKReaderThread runner : allThreads) {
				runner.close();
			}
			for(AbstractKeyJWKReaderThread runner : allThreads) {
				runner.join();
			}
		}
		
		// verify that all threads which requested a known key
		// did get the right key all the time
		for(KnownKeyJWKReaderThread runner : knownKeyThreads) {
			assertFalse(runner.isFailed());
			assertTrue(runner.getCounter() > 0);
		}

		// verify that all threads which requested an unknown key
		// did NOT get the right key all the time
		for(UnknownKeyJWKReaderThread runner : unknownKeyThreads) {
			assertFalse(runner.isFailed());
			assertEquals(0, runner.getCounter());
		}
		
		assertEquals( (iterations + 1) * 2, jwkSetSource.getCount());
	}
	
	private void run(CountingJWKSetSource<?> jwkSetSource, long jwkRefreshLimit, List<AbstractKeyJWKReaderThread> runners, long timeout) {
		// if one thread fails, stop all threads so that we can read the error message.

		long deadline = System.currentTimeMillis() + timeout;
		
		// log stats on fetch count change 
		long jwkRefreshCount = -1L;
		while(System.currentTimeMillis() < deadline) {
			boolean allThreadsAlive = true;
			for(AbstractKeyJWKReaderThread runner : runners) {
				if (!runner.isAlive()) {
					allThreadsAlive = false;
				}
			}
			
			if(!allThreadsAlive) {
				break;
			}
			try {
				Thread.sleep(100);
				
				long currentJwkRefreshCount = jwkSetSource.getCount();
				if(currentJwkRefreshCount >= jwkRefreshLimit) {
					break;
				}
				
				if(currentJwkRefreshCount != jwkRefreshCount) {
					jwkRefreshCount = currentJwkRefreshCount;
					
					long count = 0;
					for(AbstractKeyJWKReaderThread runner : runners) {
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