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


import junit.framework.TestCase;


public class HealthStatusTest extends TestCase {


	public void testConstants() {
		
		assertEquals("HEALTHY",       HealthStatus.values()[0].name());
		assertEquals("NOT_HEALTHY",   HealthStatus.values()[1].name());
		assertEquals(2, HealthStatus.values().length);
	}
}
