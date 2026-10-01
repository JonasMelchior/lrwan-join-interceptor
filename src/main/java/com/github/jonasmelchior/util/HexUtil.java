package com.github.jonasmelchior.util;

import java.util.HexFormat;

public class HexUtil {
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    public static String encodeHex(byte[] data) {
        if (data == null) return "null";
        return HEX_FORMAT.formatHex(data);
    }

    public static byte[] decodeHex(String hex) {
        if (hex == null) return new byte[0];
        String clean = hex.replaceAll("[^0-9a-fA-F]", "");
        return HEX_FORMAT.parseHex(clean);
    }

    /**
     * Reverses byte array (useful if converting between Little-Endian and Big-Endian).
     */
    public static byte[] reverse(byte[] array) {
        byte[] copy = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            copy[i] = array[array.length - 1 - i];
        }
        return copy;
    }
}
