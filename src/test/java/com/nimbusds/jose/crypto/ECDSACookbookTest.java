package com.nimbusds.jose.crypto;


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.ECKey;


/**
 * Tests EC JWS verification. Uses test vectors from the JOSE cookbook.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-22)
 */
public class ECDSACookbookTest extends TestCase {


	public void testES512Verify()
		throws Exception {

		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.3

		String json = "{"+
			"\"kty\":\"EC\","+
			"\"kid\":\"bilbo.baggins@hobbiton.example\","+
			"\"use\":\"sig\","+
			"\"crv\":\"P-521\","+
			"\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"+
			"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","+
			"\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
			"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","+
			"\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"+
			"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""+
			"}";

		ECKey jwk = ECKey.parse(json);

		String jws = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX"+
			"hhbXBsZSJ9"+
			"."+
			"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH"+
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk"+
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm"+
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"+
			"."+
			"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb"+
			"u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv"+
			"AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

		JWSObject jwsObject = JWSObject.parse(jws);

		assertEquals(JWSAlgorithm.ES512, jwsObject.getHeader().getAlgorithm());
		assertEquals("bilbo.baggins@hobbiton.example", jwsObject.getHeader().getKeyID());

		JWSVerifier verifier = new ECDSAVerifier(jwk.getX().decodeToBigInteger(), jwk.getY().decodeToBigInteger());

		assertTrue(jwsObject.verify(verifier));

		assertEquals("SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4", jwsObject.getPayload().toBase64URL().toString());
	}
}
