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


import java.io.Closeable;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * JSON Web Key (JWK) set source.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-22
 */
public interface JWKSetSource<C extends SecurityContext> extends Closeable {

	
	/**
	 * Gets the JWK set.
	 *
	 * @param refreshEvaluator Controls whether refresh of the JWK set
	 *                         cache (if utilised by the source) is
	 *                         required.
	 * @param currentTime 	   The current time, in milliseconds since the
	 *                         Unix epoch.
	 * @param context          Optional context, {@code null} if not
	 *                         required.
	 *
	 * @return The JWK set.
	 *
	 * @throws KeySourceException If JWK set retrieval failed.
	 */
	JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context)
		throws KeySourceException;
}
