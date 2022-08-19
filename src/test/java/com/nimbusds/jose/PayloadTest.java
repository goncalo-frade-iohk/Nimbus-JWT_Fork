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

package com.nimbusds.jose;


import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;


/**
 * Tests the JOSE payload class.
 */
public class PayloadTest extends TestCase {


	public void testJWSObject()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		JWSObject jwsObject = JWSObject.parse(s);

		Payload payload = new Payload(jwsObject);

		assertEquals(Payload.Origin.JWS_OBJECT, payload.getOrigin());
		assertEquals(jwsObject, payload.toJWSObject());
		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), StandardCharset.UTF_8));
	}


	public void testJWSObjectFromString() {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		Payload payload = new Payload(s);

		assertEquals(Payload.Origin.STRING, payload.getOrigin());
		assertEquals(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), StandardCharset.UTF_8));
	}


	public void testSignedJWT()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		SignedJWT signedJWT = SignedJWT.parse(s);

		Payload payload = new Payload(signedJWT);

		assertEquals(Payload.Origin.SIGNED_JWT, payload.getOrigin());
		assertEquals(signedJWT, payload.toSignedJWT());

		assertNotNull(payload.toJWSObject());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), StandardCharset.UTF_8));
	}


	public void testSignedJWTFromString()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		Payload payload = new Payload(s);

		assertEquals(Payload.Origin.STRING, payload.getOrigin());
		assertEquals(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());
		assertEquals("joe", payload.toSignedJWT().getJWTClaimsSet().getIssuer());

		assertNotNull(payload.toJWSObject());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), StandardCharset.UTF_8));
	}


	public void testRejectUnsignedJWS() {

		try {
			new Payload(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("test")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWS object must be signed", e.getMessage());
		}
	}


	public void testRejectUnsignedJWT() {

		try {
			new Payload(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build()));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWT must be signed", e.getMessage());
		}
	}


	public void testTransformer() {

		PayloadTransformer<Integer> transformer = new PayloadTransformer<Integer>() {
			@Override
			public Integer transform(final Payload payload) {

				return Integer.parseInt(payload.toString());
			}
		};

		Payload payload = new Payload("10");

		Integer out = payload.toType(transformer);

		assertEquals(new Integer(10), out);
	}
	
	
	public void testJWTClaimsSetPayloadWithTimestampClaim() throws ParseException {
		
		Date authTime = DateUtils.fromSecondsSinceEpoch(1518022800);
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.claim("auth_time", authTime)
			.build();
		
		PlainJWT plainJWT = new PlainJWT(jwtClaimsSet);
		
		String jwt = plainJWT.serialize();
		
		plainJWT = PlainJWT.parse(jwt);
		
		Payload payload = plainJWT.getPayload();
		
		assertEquals("{\"auth_time\":1518022800}", payload.toString());
	}
	
	
	public void testJSONObjectPayloadWithTimestampMember() {
		
		Map<String, Object> jsonObject = new HashMap<>();
		jsonObject.put("auth_time",1518022800L);
		
		Payload payload = new Payload(jsonObject);
		
		assertEquals(jsonObject, payload.toJSONObject());
		
		String json = payload.toString();
		
		assertEquals("{\"auth_time\":1518022800}", json);
		
		Base64URL base64URL = payload.toBase64URL();
		
		assertEquals("{\"auth_time\":1518022800}", base64URL.decodeToString());
		
		payload = new Payload(base64URL);
		
		assertEquals(jsonObject, payload.toJSONObject());
	}
}
