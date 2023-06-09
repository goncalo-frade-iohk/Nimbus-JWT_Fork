/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jwt.util;


import java.util.Date;

import junit.framework.TestCase;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest extends TestCase {
	
	
	public void testNowWithSecondsPrecision() {
		
		Date regularNow = new Date();
		
		for (int i=0; i < 100; i++) {
			Date now = DateUtils.nowWithSecondsPrecision();
			assertTrue((now.getTime() + "").endsWith("000"));
			assertTrue(DateUtils.isWithin(now, regularNow, 1));
		}
	}


	public void testToSeconds() {

		final Date date = new Date(2000L);

		assertEquals(2, DateUtils.toSecondsSinceEpoch(date));
	}


	public void testFromSeconds() {
		
		assertEquals(new Date(2000L), DateUtils.fromSecondsSinceEpoch(2));
	}


	public void testRoundTrip() {

		final Date date = new Date(100000);

		final long ts = DateUtils.toSecondsSinceEpoch(date);
		
		assertEquals(date, DateUtils.fromSecondsSinceEpoch(ts));
	}


	public void testAfterNoClockSkew_true() {

		final Date date = new Date(100001L);
		final Date reference = new Date(100000L);
		assertTrue(DateUtils.isAfter(date, reference, 0L));
	}


	public void testAfterNoClockSkew_false() {

		final Date date = new Date(100000L);
		final Date reference = new Date(100001L);
		assertFalse(DateUtils.isAfter(date, reference, 0L));
	}


	public void testBeforeNoClockSkew_true() {

		final Date date = new Date(100000L);
		final Date reference = new Date(100001L);
		assertTrue(DateUtils.isBefore(date, reference, 0L));
	}


	public void testBeforeNoClockSkew_false() {

		final Date date = new Date(100001L);
		final Date reference = new Date(100000L);
		assertFalse(DateUtils.isBefore(date, reference, 0L));
	}


	public void testAfterWithClockSkew_true() {

		final Date date = new Date(2000L);
		final Date reference = new Date(2999L);
		final long skewSeconds = 1L;
		assertTrue(DateUtils.isAfter(date, reference, skewSeconds));
	}


	public void testAfterWithClockSkew_false() {

		final Date date = new Date(2000L);
		final Date reference = new Date(3000L);
		final long skewSeconds = 1L;
		assertFalse(DateUtils.isAfter(date, reference, skewSeconds));
	}


	public void testBeforeWithClockSkew_true() {

		final Date date = new Date(2000L);
		final Date reference = new Date(1001L);
		final long skewSeconds = 1L;
		assertTrue(DateUtils.isBefore(date, reference, skewSeconds));
	}


	public void testBeforeWithClockSkew_false() {

		final Date date = new Date(2000L);
		final Date reference = new Date(1000L);
		final long skewSeconds = 1L;
		assertFalse(DateUtils.isBefore(date, reference, skewSeconds));
	}


	public void testNotBefore() {

		final long skewSeconds = 1L;

		assertTrue(DateUtils.isAfter(new Date(4001L), new Date(5000L), skewSeconds));
		assertTrue(DateUtils.isAfter(new Date(5000L), new Date(5000L), skewSeconds));
		assertTrue(DateUtils.isAfter(new Date(6000L), new Date(5000L), skewSeconds));
		assertFalse(DateUtils.isAfter(new Date(4000L), new Date(5000L), skewSeconds));
	}


	public void testForEXPClaim() {

		final Date now = new Date();

		final Date exp = new Date(now.getTime() - 30*1000L); // 30 seconds behind

		boolean valid = DateUtils.isAfter(exp, now, 60);
		assertTrue(valid);
	}


	public void testForIATClaim() {

		final Date now = new Date();

		final Date iat = new Date(now.getTime() + 30*1000L); // 30 seconds ahead

		boolean valid = DateUtils.isBefore(iat, now, 60);
		assertTrue(valid);
	}
	
	
	public void testWithin() {
		
		final Date now = new Date();
		
		final Date ref = now;
		
		assertTrue(DateUtils.isWithin(now, ref, 1));
		assertTrue(DateUtils.isWithin(now, ref, 10));
		assertTrue(DateUtils.isWithin(now, ref, 100));
	}
	
	
	public void testWithinEdges() {
		
		final Date now = new Date();
		
		final Date ref = now;
		
		final Date nineSecondsAgo = new Date(now.getTime() - 9_000);
		final Date nineSecondsAhead = new Date(now.getTime() + 9_000);
		
		assertTrue(DateUtils.isWithin(nineSecondsAgo, ref, 10));
		assertTrue(DateUtils.isWithin(nineSecondsAhead, ref, 10));
	}
	
	
	public void testWithinNegative() {
		
		final Date now = new Date();
		
		final Date ref = now;
		
		final Date tenSecondsAgo = new Date(now.getTime() - 10_000);
		final Date tenSecondsAhead = new Date(now.getTime() + 10_000);
		
		assertFalse(DateUtils.isWithin(tenSecondsAgo, ref, 9));
		assertFalse(DateUtils.isWithin(tenSecondsAhead, ref, 9));
	}
}
