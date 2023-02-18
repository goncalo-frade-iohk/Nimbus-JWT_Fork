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

import com.nimbusds.jose.jwk.JWKSet;


/**
 * JWK set reference comparison refresh evaluator.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-23
 */
class ReferenceComparisonRefreshJWKSetEvaluator extends JWKSetCacheRefreshEvaluator {
	
	
	private final JWKSet jwkSet;
	
	
	public ReferenceComparisonRefreshJWKSetEvaluator(final JWKSet jwkSet) {
		this.jwkSet = jwkSet;
	}
	
	
	@Override
	public boolean requiresRefresh(final JWKSet jwkSet) {
		// intentional reference check so that we
		// detect reloads even if the data was the same
		return jwkSet == this.jwkSet;
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(jwkSet);
	}
	
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ReferenceComparisonRefreshJWKSetEvaluator other = (ReferenceComparisonRefreshJWKSetEvaluator) obj;
		return Objects.equals(jwkSet, other.jwkSet);
	}
}
