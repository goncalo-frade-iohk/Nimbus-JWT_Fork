package com.nimbusds.jose.jwk.source;

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;


/**
 * Evaluates whether a JWK set cache requires refreshing.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-22
 */
public abstract class JWKSetCacheRefreshEvaluator {
	
	
	private static final ForceRefresh FORCE_REFRESH = new ForceRefresh();
	
	private static final NoRefresh NO_REFRESH = new NoRefresh();
	
	
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
		return new ReferenceComparisonRefresh(jwtSet);
	}
	

	/**
	 * Force-refresh JWK set cache refresh evaluator.
	 */
	protected static final class ForceRefresh extends JWKSetCacheRefreshEvaluator {

		@Override
		public boolean requiresRefresh(final JWKSet jwkSet) {
			return true;
		}

		@Override
		public boolean equals(Object obj) {
			return obj instanceof ForceRefresh;
		}
		
		@Override
		public int hashCode() {
			return 0;
		}
	}
	
	
	/**
	 * No-refresh JWK set cache refresh evaluator.
	 */
	protected static class NoRefresh extends JWKSetCacheRefreshEvaluator {

		@Override
		public boolean requiresRefresh(JWKSet jwkSet) {
			return false;
		}


		@Override
		public boolean equals(Object obj) {
			return obj instanceof NoRefresh;
		}
		
		@Override
		public int hashCode() {
			return 0;
		}

	}
	
	
	/**
	 * JWK set reference comparison refresh evaluator.
	 */
	protected static class ReferenceComparisonRefresh extends JWKSetCacheRefreshEvaluator {

		private final JWKSet jwkSet;
		
		public ReferenceComparisonRefresh(final JWKSet jwkSet) {
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
			ReferenceComparisonRefresh other = (ReferenceComparisonRefresh) obj;
			return Objects.equals(jwkSet, other.jwkSet);
		}
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