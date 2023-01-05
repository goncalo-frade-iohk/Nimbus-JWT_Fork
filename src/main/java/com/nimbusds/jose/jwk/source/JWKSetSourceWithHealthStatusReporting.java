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

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;
import com.nimbusds.jose.util.health.HealthStatus;


/**
 * Decorates a {@linkplain JWKSetSource} with health status reporting.
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2022-11-22
 */
@ThreadSafe
public class JWKSetSourceWithHealthStatusReporting<C extends SecurityContext> extends JWKSetSourceWrapper<C> {
	
	
	private final HealthReportListener<JWKSetSourceWithHealthStatusReporting<C>, C> healthReportListener;
	
	
	/**
	 * Creates a new JWK set source with health status reporting to the
	 * specified listener.
	 *
	 * @param source               The JWK set source to wrap. Must not be
	 *                             {@code null}.
	 * @param healthReportListener The health report listener. Must not be
	 *                             {@code null}.
	 */
	public JWKSetSourceWithHealthStatusReporting(final JWKSetSource<C> source,
						     final HealthReportListener<JWKSetSourceWithHealthStatusReporting<C>, C> healthReportListener) {
		super(source);
		Objects.requireNonNull(healthReportListener);
		this.healthReportListener = healthReportListener;
	}
	
	
	@Override
	public JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context)
		throws KeySourceException {
		
		JWKSet jwkSet;
		try {
			jwkSet = getSource().getJWKSet(refreshEvaluator, currentTime, context);
			healthReportListener.notify(new HealthReport<>(this, HealthStatus.HEALTHY, currentTime, context));
		} catch (Exception e) {
			healthReportListener.notify(new HealthReport<>(this, HealthStatus.NOT_HEALTHY, e, currentTime, context));
			throw e;
		}

		return jwkSet;
	}
}
