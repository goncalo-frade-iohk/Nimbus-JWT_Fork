/*
 * nimbus-jose-jwt 
 *
 * Copyright 2012-2018, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.jwk.gen;


import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.util.DateUtils;

import junit.framework.TestCase;


/**
 * @author Tim McLean
 * @version 2023-01-02
 */
public class OctetKeyPairGeneratorTest extends TestCase {
	
	
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
	private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);


	public void testX25519GenMinimal()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.X25519)
			.generate();

		assertEquals(Curve.X25519, okp.getCurve());

		assertNull(okp.getKeyUse());
		assertNull(okp.getKeyOperations());
		assertNull(okp.getAlgorithm());
		assertNull(okp.getKeyID());
		assertNull(okp.getExpirationTime());
		assertNull(okp.getNotBeforeTime());
		assertNull(okp.getIssueTime());
		assertNull(okp.getKeyStore());

		byte[] privateKeyBytes = okp.getD().decode();
		assertEquals(privateKeyBytes.length, 32);
	}


	public void testX25519GenWithParams_explicitKeyID()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.X25519)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.DECRYPT))
			.algorithm(JWEAlgorithm.ECDH_ES)
			.keyID("1")
			.generate();

		assertEquals(Curve.X25519, okp.getCurve());

		assertEquals(KeyUse.ENCRYPTION, okp.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.DECRYPT), okp.getKeyOperations());
		assertEquals(JWEAlgorithm.ECDH_ES, okp.getAlgorithm());
		assertEquals("1", okp.getKeyID());
		assertNull(okp.getKeyStore());
	}


	public void testX25519GenWithParams_thumbprintKeyID()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.X25519)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.DECRYPT))
			.algorithm(JWEAlgorithm.ECDH_ES)
			.keyIDFromThumbprint(true)
			.generate();

		assertEquals(Curve.X25519, okp.getCurve());

		assertEquals(KeyUse.ENCRYPTION, okp.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.DECRYPT), okp.getKeyOperations());
		assertEquals(JWEAlgorithm.ECDH_ES, okp.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(okp).toString(), okp.getKeyID());
		assertNull(okp.getKeyStore());
	}


	// The x and d values that are generated should all be distinct
	public void testX25519Distinctness()
		throws JOSEException  {

		Set<Base64URL> values = new HashSet<>();

		OctetKeyPairGenerator gen = new OctetKeyPairGenerator(Curve.X25519);

		for (int i=0; i<100; i++) {

			OctetKeyPair k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
		}
	}


	public void testEd25519GenMinimal()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.Ed25519)
			.generate();

		assertEquals(Curve.Ed25519, okp.getCurve());

		assertNull(okp.getKeyUse());
		assertNull(okp.getKeyOperations());
		assertNull(okp.getAlgorithm());
		assertNull(okp.getKeyID());
		assertNull(okp.getKeyStore());
	}


	public void testEd25519GenWithParams_explicitKeyID()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.Ed25519)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.EdDSA)
			.keyID("1")
			.generate();

		assertEquals(Curve.Ed25519, okp.getCurve());

		assertEquals(KeyUse.SIGNATURE, okp.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), okp.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, okp.getAlgorithm());
		assertEquals("1", okp.getKeyID());
		assertNull(okp.getKeyStore());
	}


	public void testEd25519GenWithParams_thumbprintKeyID()
		throws JOSEException  {

		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.Ed25519)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.EdDSA)
			.keyIDFromThumbprint(true)
			.generate();

		assertEquals(Curve.Ed25519, okp.getCurve());

		assertEquals(KeyUse.SIGNATURE, okp.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), okp.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, okp.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(okp).toString(), okp.getKeyID());
		assertNull(okp.getKeyStore());
	}


	// The x and d values that are generated should all be distinct
	public void testEd25519Distinctness()
		throws JOSEException  {

		Set<Base64URL> values = new HashSet<>();

		OctetKeyPairGenerator gen = new OctetKeyPairGenerator(Curve.Ed25519);

		for (int i=0; i<100; i++) {

			OctetKeyPair k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
		}
	}
	
	
	public void testGenWithTimestamps() throws JOSEException {
		
		OctetKeyPair okp = new OctetKeyPairGenerator(Curve.Ed25519)
			.keyUse(KeyUse.SIGNATURE)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.generate();
		
		assertEquals(EXP, okp.getExpirationTime());
		assertEquals(NBF, okp.getNotBeforeTime());
		assertEquals(IAT, okp.getIssueTime());
	}
}
