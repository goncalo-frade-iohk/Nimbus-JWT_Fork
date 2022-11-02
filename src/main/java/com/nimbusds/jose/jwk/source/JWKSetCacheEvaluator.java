package com.nimbusds.jose.jwk.source;

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;

public abstract class JWKSetCacheEvaluator {
	
	private static final AlwaysRefresh ALWAYS = new AlwaysRefresh();
	private static final NeverRefresh NEVER = new NeverRefresh();
	
	public static JWKSetCacheEvaluator always() {
		return ALWAYS;
	}

	public static JWKSetCacheEvaluator never() {
		return NEVER;
	}
	
	public static JWKSetCacheEvaluator optional(JWKSet jwtSet) {
		return new OptionalRefresh(jwtSet);
	}
	

	public static final class AlwaysRefresh extends JWKSetCacheEvaluator {

		@Override
		public boolean performRefresh(JWKSet set) {
			return true;
		}

		@Override
		public boolean equals(Object obj) {
			return obj instanceof AlwaysRefresh;
		}
		
		@Override
		public int hashCode() {
			return 0;
		}
	}

	public static class NeverRefresh extends JWKSetCacheEvaluator {

		@Override
		public boolean performRefresh(JWKSet set) {
			return false;
		}


		@Override
		public boolean equals(Object obj) {
			return obj instanceof NeverRefresh;
		}
		
		@Override
		public int hashCode() {
			return 0;
		}

	}

	public static class OptionalRefresh extends JWKSetCacheEvaluator {

		private final JWKSet jwkSet;
		
		public OptionalRefresh(JWKSet jwkSet) {
			this.jwkSet = jwkSet;
		}
		
		@Override
		public boolean performRefresh(JWKSet set) {
			// intentional reference check so that we 
			// detect reloads even if the data was the same
			return set == jwkSet;
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
			OptionalRefresh other = (OptionalRefresh) obj;
			return Objects.equals(jwkSet, other.jwkSet);
		}
		
	}
	
	public abstract boolean performRefresh(JWKSet set);
}