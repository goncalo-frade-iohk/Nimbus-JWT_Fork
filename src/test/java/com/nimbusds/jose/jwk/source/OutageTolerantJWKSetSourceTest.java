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


import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;

public class OutageTolerantJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private OutageTolerantJWKSetSource<SecurityContext> source;
	
	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, 10 * 3600 * 1000);
	}

	@Test
	public void testShouldUseDelegate() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
	}

	@Test
	public void testShouldUseDelegateWhenCached() throws Exception {
		JWKSet last = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenReturn(last);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), last);
	}

	@Test
	public void testShouldUseCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(false, System.currentTimeMillis(), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldNotUseExpiredCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(false, System.currentTimeMillis(), context);

		try {
			source.getJWKSet(false, CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST", e.getMessage());
		}
	}

	@Test
	public void testShouldGetBaseProvider() {
		assertEquals(source.getSource(), wrappedJWKSetSource);
	}
}
