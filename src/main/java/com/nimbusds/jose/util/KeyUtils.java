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

package com.nimbusds.jose.util;


import javax.crypto.SecretKey;


/**
 * JCA key utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-09-24
 */
public class KeyUtils {
	
	
	/**
	 * Returns the specified secret key as a wrapped secret key with its
	 * algorithm set to "AES". If the input key algorithm is "AES" it is
	 * returned unmodified.
	 *
	 * @param secretKey The secret key, {@code null} if not specified.
	 *
	 * @return The AES secret key, {@code null} if not specified.
	 */
	public static SecretKey toAESKey(final SecretKey secretKey) {
		
		if (secretKey == null || secretKey.getAlgorithm().equals("AES")) {
			return secretKey;
		}
		
		return new SecretKey() {
			@Override
			public String getAlgorithm() {
				return "AES";
			}
			
			
			@Override
			public String getFormat() {
				return secretKey.getFormat();
			}
			
			
			@Override
			public byte[] getEncoded() {
				return secretKey.getEncoded();
			}
		};
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private KeyUtils() {}
}
