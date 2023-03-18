package com.nimbusds.jose.crypto.utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Secp256k1Scalar {
    public static byte[] reverseB32(byte[] inputBytes) {
        byte[] reversedBytes = new byte[inputBytes.length];

        for (int i = 0; i < inputBytes.length; i++) {
            reversedBytes[inputBytes.length - i - 1] = inputBytes[i];
        }
        return reversedBytes;
    }

    private static String byteArrayToHex(byte[] byteArray) {
        return new BigInteger(1, byteArray).toString(16);
    }

    public static byte[] hexStringToByteArray(String hexInput) {
        int len = hexInput.length();
        if (len % 2 != 0) {
            hexInput = "0" + hexInput;
            len++;
        }
        byte[] byteArray = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexInput.charAt(i), 16) << 4)
                    + Character.digit(hexInput.charAt(i + 1), 16));
        }
        return byteArray;
    }

}
