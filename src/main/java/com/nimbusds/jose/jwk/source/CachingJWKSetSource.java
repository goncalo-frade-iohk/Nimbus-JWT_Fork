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


import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;
import com.nimbusds.jose.util.events.EventListener;


/**
 * Caching {@linkplain JWKSetSource}. Blocks during cache updates.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-08
 */
@ThreadSafe
public class CachingJWKSetSource<C extends SecurityContext> extends AbstractCachingJWKSetSource<C> {
	
	
	static class AbstractCachingJWKSetSourceEvent<C extends SecurityContext> extends AbstractJWKSetSourceEvent<CachingJWKSetSource<C>, C> {
		
		private final int threadQueueLength;
		
		public AbstractCachingJWKSetSourceEvent(final CachingJWKSetSource<C> source,
							final int threadQueueLength,
							final C context) {
			super(source, context);
			this.threadQueueLength = threadQueueLength;
		}
		
		
		/**
		 * Returns an estimate of the number of queued threads.
		 *
		 * @return An estimate of the number of queued threads.
		 */
		public int getThreadQueueLength() {
			return threadQueueLength;
		}
	}
	
	
	/**
	 * JWK set cache refresh initiated event.
	 */
	public static class RefreshInitiatedEvent<C extends SecurityContext> extends AbstractCachingJWKSetSourceEvent<C> {
		
		private RefreshInitiatedEvent(final CachingJWKSetSource<C> source, final int queueLength, final C context) {
			super(source, queueLength, context);
		}
	}
	
	
	/**
	 * JWK set cache refresh completed event.
	 */
	public static class RefreshCompletedEvent<C extends SecurityContext> extends AbstractCachingJWKSetSourceEvent<C> {
		
		private final JWKSet jwkSet;
		
		private RefreshCompletedEvent(final CachingJWKSetSource<C> source,
					      final JWKSet jwkSet,
					      final int queueLength,
					      final C context) {
			super(source, queueLength, context);
			Objects.requireNonNull(jwkSet);
			this.jwkSet = jwkSet;
		}
		
		
		/**
		 * Returns the refreshed JWK set.
		 *
		 * @return The refreshed JWK set.
		 */
		public JWKSet getJWKSet() {
			return jwkSet;
		}
	}
	
	
	/**
	 * Waiting for a JWK set cache refresh to complete on another thread
	 * event.
	 */
	public static class WaitingForRefreshEvent<C extends SecurityContext> extends AbstractCachingJWKSetSourceEvent<C> {
		
		private WaitingForRefreshEvent(final CachingJWKSetSource<C> source, final int queueLength, final C context) {
			super(source, queueLength, context);
		}
	}
	
	
	/**
	 * Unable to refresh the JWK set cache event.
	 */
	public static class UnableToRefreshEvent<C extends SecurityContext> extends AbstractJWKSetSourceEvent<CachingJWKSetSource<C>, C> {
		
		private UnableToRefreshEvent(final CachingJWKSetSource<C> source, final C context) {
			super(source, context);
		}
	}
	
	
	/**
	 * JWK set cache refresh timed out event.
	 */
	public static class RefreshTimedOutEvent<C extends SecurityContext> extends AbstractCachingJWKSetSourceEvent<C> {
		
		private RefreshTimedOutEvent(final CachingJWKSetSource<C> source, final int queueLength, final C context) {
			super(source, queueLength, context);
		}
	}
	
	
	private final ReentrantLock lock = new ReentrantLock();

	private final long cacheRefreshTimeout;
	
	private final EventListener<CachingJWKSetSource<C>, C> eventListener;
	
	
	/**
	 * Creates a new caching JWK set source.
	 *
	 * @param source	      The JWK set source to decorate. Must not
	 *                            be {@code null}.
	 * @param timeToLive          The time to live of the cached JWK set,
	 * 	                      in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 * @param eventListener       The event listener, {@code null} if not
	 *                            specified.
	 */
	public CachingJWKSetSource(final JWKSetSource<C> source,
				   final long timeToLive,
				   final long cacheRefreshTimeout,
				   final EventListener<CachingJWKSetSource<C>, C> eventListener) {
		super(source, timeToLive);
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		this.eventListener = eventListener;
	}

	
	@Override
	public JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context) throws KeySourceException {
		CachedObject<JWKSet> cache = getCachedJWKSet();
		if (cache == null) {
			return loadJWKSetBlocking(JWKSetCacheRefreshEvaluator.noRefresh(), currentTime, context);
		}

		JWKSet jwkSet = cache.get();
		if (refreshEvaluator.requiresRefresh(jwkSet)) {
			return loadJWKSetBlocking(refreshEvaluator, currentTime, context);
		}
		
		if (cache.isExpired(currentTime)) {
			return loadJWKSetBlocking(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet), currentTime, context);
		}

		return cache.get();
	}
	
	
	/**
	 * Returns the cache refresh timeout.
	 *
	 * @return The cache refresh timeout, in milliseconds.
	 */
	public long getCacheRefreshTimeout() {
		return cacheRefreshTimeout;
	}
	
	
	/**
	 * Loads and caches the JWK set, with blocking.
	 *
	 * @param refreshEvaluator The JWK set cache refresh evaluator.
	 * @param currentTime      The current time, in milliseconds since the
	 *                         Unix epoch.
	 * @param context          Optional context, {@code null} if not
	 *                         required.
	 *
	 * @return The loaded and cached JWK set.
	 *
	 * @throws KeySourceException If retrieval failed.
	 */
	JWKSet loadJWKSetBlocking(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context)
		throws KeySourceException {
		
		// Synchronize so that the first thread to acquire the lock
		// exclusively gets to call the underlying source.
		// Other (later) threads must wait until the result is ready.
		//
		// If the first to get the lock fails within the waiting interval,
		// subsequent threads will attempt to update the cache themselves.
		//
		// This approach potentially blocks a number of threads,
		// but requesting the same data downstream is not better, so
		// this is a necessary evil.

		final CachedObject<JWKSet> cache;
		try {
			if (lock.tryLock()) {
				try {
					// We hold the lock, so safe to update it now, 
					// Check evaluator, another thread might have already updated the JWKs
					CachedObject<JWKSet> cachedJWKSet = getCachedJWKSet();
					if (cachedJWKSet == null || refreshEvaluator.requiresRefresh(cachedJWKSet.get())) {
	
						if (eventListener != null) {
							eventListener.notify(new RefreshInitiatedEvent<>(this, lock.getQueueLength(), context));
						}
						
						CachedObject<JWKSet> result = loadJWKSetNotThreadSafe(refreshEvaluator, currentTime, context);
						
						if (eventListener != null) {
							eventListener.notify(new RefreshCompletedEvent<>(this, result.get(), lock.getQueueLength(), context));
						}
						
						cache = result;
					} else {
						// load updated value
						cache = cachedJWKSet;
					}
					
				} finally {
					lock.unlock();
				}
			} else {
				// Lock held by another thread, wait for refresh timeout
				if (eventListener != null) {
					eventListener.notify(new WaitingForRefreshEvent<>(this, lock.getQueueLength(), context));
				}

				if (lock.tryLock(getCacheRefreshTimeout(), TimeUnit.MILLISECONDS)) {
					try {
						// Check evaluator, another thread have most likely already updated the JWKs
						CachedObject<JWKSet> cachedJWKSet = getCachedJWKSet();
						if (cachedJWKSet == null || refreshEvaluator.requiresRefresh(cachedJWKSet.get())) {
							// Seems cache was not updated.
							// We hold the lock, so safe to update it now
							if (eventListener != null) {
								eventListener.notify(new RefreshInitiatedEvent<>(this, lock.getQueueLength(), context));
							}
							
							cache = loadJWKSetNotThreadSafe(refreshEvaluator, currentTime, context);
							
							if (eventListener != null) {
								eventListener.notify(new RefreshCompletedEvent<>(this, cache.get(), lock.getQueueLength(), context));
							}
						} else {
							// load updated value
							cache = cachedJWKSet;
						}
					} finally {
						lock.unlock();
					}
				} else {

					if (eventListener != null) {
						eventListener.notify(new RefreshTimedOutEvent<>(this, lock.getQueueLength(), context));
					}
					
					throw new JWKSetUnavailableException("Timeout while waiting for cache refresh (" + cacheRefreshTimeout + "ms exceeded)");
				}
			}

			if (cache != null && cache.isValid(currentTime)) {
				return cache.get();
			}
			
			if (eventListener != null) {
				eventListener.notify(new UnableToRefreshEvent<>(this, context));
			}
			
			throw new JWKSetUnavailableException("Unable to refresh cache");
			
		} catch (InterruptedException e) {
			
			Thread.currentThread().interrupt(); // Restore interrupted state to make Sonar happy

			throw new JWKSetUnavailableException("Interrupted while waiting for cache refresh", e);
		}
	}
	
	
	/**
	 * Loads the JWK set from the wrapped source and caches it. Should not
	 * be run by more than one thread at a time.
	 *
	 * @param refreshEvaluator The JWK set cache refresh evaluator.
	 * @param currentTime      The current time, in milliseconds since the
	 *                         Unix epoch.
	 * @param context          Optional context, {@code null} if not
	 *                         required.
	 *
	 * @return Reference to the cached JWK set.
	 *
	 * @throws KeySourceException If loading failed.
	 */
	CachedObject<JWKSet> loadJWKSetNotThreadSafe(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context)
		throws KeySourceException {
		
		JWKSet jwkSet = getSource().getJWKSet(refreshEvaluator, currentTime, context);

		return cacheJWKSet(jwkSet, currentTime);
	}
	
	
	/**
	 * Returns the lock.
	 *
	 * @return The lock.
	 */
	ReentrantLock getLock() {
		return lock;
	}
}
