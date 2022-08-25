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


import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.proc.SecurityContext;

public class RetryingJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private RetryingJWKSetSource<SecurityContext> source;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource);
	}

	@Test
	public void testShouldReturnListOnSuccess() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldRetryWhenUnavailable() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null)).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldNotRetryMoreThanOnce() throws Exception {
		when(wrappedJWKSetSource.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null));

		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST!", e.getMessage());
		} finally {
			verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		}
	}

	
	@Test
	public void testShouldGetBaseProvider() {
		assertEquals(source.getSource(), wrappedJWKSetSource);
	}
}
