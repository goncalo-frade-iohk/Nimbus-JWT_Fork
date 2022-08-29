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

package com.nimbusds.jose.util.health;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;


public class HealthReportTest extends TestCase {
	
	
	private static final Object SOURCE = new Object();
	private static final Exception EXCEPTION = new KeySourceException("JWK set retrieval failed");
	private static final long TIMESTAMP = new Date().getTime();


	public void testConstructor_healthy() {
		HealthReport<Object, ?> report = new HealthReport<>(SOURCE, HealthStatus.HEALTHY, TIMESTAMP, null);
		assertEquals(SOURCE, report.getSource());
		assertEquals(HealthStatus.HEALTHY, report.getHealthStatus());
		assertNull(report.getException());
		assertEquals(TIMESTAMP, report.getTimestamp());
		assertNull(report.getContext());
		
		assertEquals("HealthReport{source=" + SOURCE + ", status=HEALTHY, exception=null, timestamp=" + TIMESTAMP + ", context=null}", report.toString());
	}


	public void testConstructor_notHealthy() {
		HealthReport<Object, ?> report = new HealthReport<>(SOURCE, HealthStatus.NOT_HEALTHY, EXCEPTION, TIMESTAMP, null);
		assertEquals(SOURCE, report.getSource());
		assertEquals(HealthStatus.NOT_HEALTHY, report.getHealthStatus());
		assertEquals(EXCEPTION, report.getException());
		assertEquals(TIMESTAMP, report.getTimestamp());
		assertNull(report.getContext());
		
		assertEquals("HealthReport{source=" + SOURCE + ", status=NOT_HEALTHY, exception=com.nimbusds.jose.KeySourceException: JWK set retrieval failed, timestamp=" + TIMESTAMP + ", context=null}", report.toString());
	}
	
	
	public void testConstructor_withContext() {
		
		SecurityContext context = new SimpleSecurityContext();
		
		HealthReport<Object, SecurityContext> report = new HealthReport<>(SOURCE, HealthStatus.HEALTHY, TIMESTAMP, context);
		
		assertEquals(SOURCE, report.getSource());
		assertEquals(HealthStatus.HEALTHY, report.getHealthStatus());
		assertNull(report.getException());
		assertEquals(TIMESTAMP, report.getTimestamp());
		assertEquals(context, report.getContext());
	}
	
	
	public void testStatusMustNotBeNull() {
		
		try {
			new HealthReport(SOURCE, null, TIMESTAMP, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testRejectHealthyWithException() {
		
		try {
			new HealthReport(SOURCE, HealthStatus.HEALTHY, EXCEPTION, TIMESTAMP, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Exception not accepted for a healthy status", e.getMessage());
		}
	}
}
