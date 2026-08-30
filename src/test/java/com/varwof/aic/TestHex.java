package com.varwof.aic;

/**
 * Hex helpers for the test suite (mirror encoding/hex in Go).
 */
public final class TestHex {
    private TestHex() {
    }

    public static String encodeHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16));
            sb.append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    public static byte[] decodeHex(String s) {
        s = s.replaceAll("\\s+", "");
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}