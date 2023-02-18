package com.nimbusds.jose.jwk.source;

import com.nimbusds.jose.jwk.JWKSet;


/**
 * Evaluates whether a JWK set cache requires refreshing.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-23
 */
public abstract class JWKSetCacheRefreshEvaluator {
	
	
	private static final ForceRefreshJWKSetCacheEvaluator FORCE_REFRESH = new ForceRefreshJWKSetCacheEvaluator();
	
	private static final NoRefreshJWKSetCacheEvaluator NO_REFRESH = new NoRefreshJWKSetCacheEvaluator();
	
	
	/**
	 * Returns a force-refresh evaluator.
	 *
	 * @return The force-refresh evaluator.
	 */
	public static JWKSetCacheRefreshEvaluator forceRefresh() {
		return FORCE_REFRESH;
	}
	
	
	/**
	 * Returns a no-refresh evaluator.
	 *
	 * @return The no-refresh evaluator.
	 */
	public static JWKSetCacheRefreshEvaluator noRefresh() {
		return NO_REFRESH;
	}
	
	
	/**
	 * Returns a reference comparison evaluator for the specified JWK set.
	 *
	 * @param jwtSet The JWK set.
	 *
	 * @return The reference comparison evaluator.
	 */
	public static JWKSetCacheRefreshEvaluator referenceComparison(final JWKSet jwtSet) {
		return new ReferenceComparisonRefreshJWKSetEvaluator(jwtSet);
	}
	
	
	/**
	 * Returns {@code true} if refresh of the JWK set is required.
	 *
	 * @param jwkSet The JWK set. Must not be {@code null}.
	 *
	 * @return {@code true} if refresh is required, {@code false} if not.
	 */
	public abstract boolean requiresRefresh(final JWKSet jwkSet);
}