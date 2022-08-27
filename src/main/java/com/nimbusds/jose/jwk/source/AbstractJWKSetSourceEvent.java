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


import java.util.Objects;

import com.nimbusds.jose.proc.SecurityContext;


/**
 * Abstract {@linkplain JWKSetSourceEvent}.
 *
 * @version 2022-08-27
 * @author Vladimir Dzhuvinov
 */
class AbstractJWKSetSourceEvent<S extends JWKSetSource<C>, C extends SecurityContext> implements JWKSetSourceEvent<S,C> {
	
	
	private final S source;
	
	private final C securityContext;
	
	
	/**
	 * Creates a new JWK set source event.
	 *
	 * @param source          The event source. Must not be {@code null}.
	 * @param securityContext Optional context, {@code null} if not
	 *                        specified.
	 */
	AbstractJWKSetSourceEvent(final S source, final C securityContext) {
		Objects.requireNonNull(securityContext);
		this.source = source;
		this.securityContext = securityContext;
	}
	
	
	@Override
	public S getJWKSetSource() {
		return source;
	}
	
	
	@Override
	public C getSecurityContext() {
		return securityContext;
	}
}
