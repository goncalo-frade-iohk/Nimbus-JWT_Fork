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


import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;
import com.nimbusds.jose.util.health.HealthStatus;


public class JWKSetSourceWithHealthReportListenerTest extends AbstractWrappedJWKSetSourceTest {

	private JWKSetSourceWithHealthStatusReporting<SecurityContext> source;
	
	private static class HealthListener implements HealthReportListener<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> {
		
		private HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> lastReport;
		
		HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> getLastReport() {
			return lastReport;
		}
		
		@Override
		public void notify(HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> healthReport) {
			lastReport = healthReport;
		}
	}
	
	private final HealthListener listener = new HealthListener();
	
	@Before
	public void setUp() throws Exception {
		
		super.setUp();
		
		source = new JWKSetSourceWithHealthStatusReporting<>(wrappedJWKSetSource, listener);
	}

	@Test
	public void nullReportPriorToInvocation() throws Exception {
		
		Mockito.verify(wrappedJWKSetSource, times(0)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		
		assertNull(listener.getLastReport());
	}

	@Test
	public void reportHealthyStatus() throws Exception {
		
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		// attempt to get JWK set
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		
		assertEquals(HealthStatus.HEALTHY, listener.getLastReport().getHealthStatus());

		// expected behavior: the health provider did not attempt to refresh
		// a good health status.
		Mockito.verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		
		assertEquals(HealthStatus.HEALTHY, listener.getLastReport().getHealthStatus());
	}

	@Test
	public void reportNotHealthyStatus() throws Exception {
		
		Exception exception = new KeySourceException("test");
		
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenThrow(exception);

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
			fail();
		} catch (KeySourceException e) {
			assertEquals("test", e.getMessage());
		}
		
		assertEquals(HealthStatus.NOT_HEALTHY, listener.getLastReport().getHealthStatus());
		assertEquals(exception, listener.getLastReport().getException());
		
		Mockito.verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
	}
}
