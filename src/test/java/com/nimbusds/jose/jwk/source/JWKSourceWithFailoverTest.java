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

package com.nimbusds.jose.jwk.source;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.junit.Test;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.SecurityContext;

public class JWKSourceWithFailoverTest {

	@Test
	public void testClosesDelegates() throws KeySourceException, IOException {
		JWKSetSource<SecurityContext> jwkSource = mock(JWKSetSource.class);
		JWKSetSource<SecurityContext> failoverJWKSource = mock(JWKSetSource.class);
		
		JWKSourceWithFailover<SecurityContext> jwkSourceWithFailover = new JWKSourceWithFailover<>(new JWKSetBasedJWKSource<>(jwkSource), new JWKSetBasedJWKSource<>(failoverJWKSource));

		jwkSourceWithFailover.close();

		verify(jwkSource, only()).close();
		verify(failoverJWKSource, only()).close();
	}

}
