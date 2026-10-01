package com.github.jonasmelchior.model;

import com.github.jonasmelchior.util.HexUtil;
import java.util.Arrays;

public record JoinRequestFrame(
        byte mhdr,
        byte[] joinEui,    // 8 bytes (little endian in frame)
        byte[] devEui,     // 8 bytes (little endian in frame)
        byte[] devNonce,   // 2 bytes (little endian in frame)
        byte[] mic,        // 4 bytes
        byte[] rawPayload  // 23 bytes
) {
    public String getDevEuiHex() {
        // Typically displayed big-endian for human readability (reverse of over-the-air little-endian representation)
        return HexUtil.encodeHex(HexUtil.reverse(devEui));
    }

    public String getJoinEuiHex() {
        return HexUtil.encodeHex(HexUtil.reverse(joinEui));
    }

    public String getDevNonceHex() {
        return HexUtil.encodeHex(devNonce);
    }

    public String getMicHex() {
        return HexUtil.encodeHex(mic);
    }
}
