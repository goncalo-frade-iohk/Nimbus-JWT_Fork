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


import java.io.*;
import java.nio.charset.Charset;


/**
 * Input / output utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2020-02-23
 */
public class IOUtils {
	
	
	/**
	 * Reads the specified input stream into a string using UTF-8 character
	 * set encoding.
	 *
	 * @param stream The input stream. Must not be {@code null}.
	 *
	 * @return The string.
	 *
	 * @throws IOException If an input exception is encountered.
	 */
	public static String readInputStreamToString(final InputStream stream)
		throws IOException {
		
		return readInputStreamToString(stream, StandardCharset.UTF_8);
	}
	
	
	/**
	 * Reads the specified input stream into a string.
	 *
	 * @param stream  The input stream. Must not be {@code null}.
	 * @param charset The expected character set. Must not be {@code null}.
	 *
	 * @return The string.
	 *
	 * @throws IOException If an input exception is encountered.
	 */
	public static String readInputStreamToString(final InputStream stream, final Charset charset)
		throws IOException {
		
		final int bufferSize = 1024;
		final char[] buffer = new char[bufferSize];
		final StringBuilder out = new StringBuilder();
		
		try (Reader in = new InputStreamReader(stream, charset)) {
			while (true) {
				int rsz = in.read(buffer, 0, buffer.length);
				if (rsz < 0)
					break;
				out.append(buffer, 0, rsz);
			}
			return out.toString();
		}
	}
	
	
	/**
	 * Reads the content of the specified file into a string using UTF-8
	 * character set encoding.
	 *
	 * @param file The file. Must not be {@code null}.
	 *
	 * @return The string.
	 *
	 * @throws IOException If an input exception is encountered.
	 */
	public static String readFileToString(final File file)
		throws IOException {
		
		return readInputStreamToString(new FileInputStream(file));
	}
	
	
	/**
	 * Reads the content of the specified file into a string.
	 *
	 * @param file    The file. Must not be {@code null}.
	 * @param charset The expected character set. Must not be {@code null}.
	 *
	 * @return The string.
	 *
	 * @throws IOException If an input exception is encountered.
	 */
	public static String readFileToString(final File file, final Charset charset)
		throws IOException {
		
		return readInputStreamToString(new FileInputStream(file), charset);
	}
	
	
	/**
	 * Closes a {@linkplain Closeable} without throwing an
	 * {@linkplain IOException}.
	 * 
	 * @param closeable The closeable.
	 */
	public static void closeSilently(final Closeable closeable) {
		try {
			closeable.close();
		} catch (IOException e) {
			// ignore
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private IOUtils() {}
}
