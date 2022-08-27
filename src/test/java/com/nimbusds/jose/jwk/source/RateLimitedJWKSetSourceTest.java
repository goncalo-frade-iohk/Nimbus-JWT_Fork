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


import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;

import com.nimbusds.jose.proc.SecurityContext;

public class RateLimitedJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private static final int MIN_TIME_INTERVAL = 30_000;
	
	private final List<RateLimitedJWKSetSource.RateLimitedEvent<SecurityContext>> events = new LinkedList<>();
	
	private final JWKSetSourceEventListener<RateLimitedJWKSetSource<SecurityContext>,SecurityContext> eventListener =
		new JWKSetSourceEventListener<RateLimitedJWKSetSource<SecurityContext>, SecurityContext>() {
			@Override
			public void receive(JWKSetSourceEvent<RateLimitedJWKSetSource<SecurityContext>, SecurityContext> event) {
				events.add((RateLimitedJWKSetSource.RateLimitedEvent<SecurityContext>) event);
			}
		};
	
	private RateLimitedJWKSetSource<SecurityContext> source;
	
	@Test
	public void rateLimitedWhenEmptyBucket() throws Exception {
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL);
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(false, System.currentTimeMillis(), context));
		assertEquals(jwkSet, source.getJWKSet(false, System.currentTimeMillis() + 1, context));
		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
	}
	
	@Test
	public void rateLimitedWhenEmptyBucket_withListener() throws Exception {
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(false, System.currentTimeMillis(), context));
		assertTrue(events.isEmpty());
		assertEquals(jwkSet, source.getJWKSet(false, System.currentTimeMillis() + 1, context));
		assertTrue(events.isEmpty());
		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
		assertEquals(1, events.size());
	}

	@Test
	public void rateLimitedWhenEmptyBucket_forceUpdate() throws Exception {
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(true), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(true, System.currentTimeMillis(), context));
		assertEquals(jwkSet, source.getJWKSet(true, System.currentTimeMillis() + 1, context));
		try {
			source.getJWKSet(true, System.currentTimeMillis(), context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
		assertEquals(1, events.size());
	}
	
	@Test
	public void refillBucket() throws Exception {
		
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL);
		
		long time = System.currentTimeMillis();
		
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(false, time, context));
		assertEquals(jwkSet, source.getJWKSet(false, time + 1, context));
		try {
			source.getJWKSet(false, time + 2, context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
		
		assertEquals(source.getJWKSet(false, time + MIN_TIME_INTERVAL, context), jwkSet);
	}
	
	@Test
	public void refillBucket_withListener() throws Exception {
		
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL, eventListener);
		
		long time = System.currentTimeMillis();
		
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(false, time, context));
		assertTrue(events.isEmpty());
		assertEquals(jwkSet, source.getJWKSet(false, time + 1, context));
		assertTrue(events.isEmpty());
		try {
			source.getJWKSet(false, time + 2, context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
		assertEquals(1, events.size());
		
		assertEquals(source.getJWKSet(false, time + MIN_TIME_INTERVAL, context), jwkSet);
		assertEquals(1, events.size());
	}

	@Test
	public void bucketTokensAvailable() throws Exception {
		
		source = new RateLimitedJWKSetSource<>(wrappedJWKSetSource, MIN_TIME_INTERVAL, eventListener);
		
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		
		assertEquals(jwkSet, source.getJWKSet(false, System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource).getJWKSet(eq(false), anyLong(), anySecurityContext());
		
		assertTrue(events.isEmpty());
	}
}
