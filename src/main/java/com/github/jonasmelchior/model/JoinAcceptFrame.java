package com.github.jonasmelchior.model;

import com.github.jonasmelchior.util.HexUtil;

public record JoinAcceptFrame(
        byte mhdr,
        byte[] joinNonce,   // 3 bytes
        byte[] netId,       // 3 bytes
        byte[] devAddr,     // 4 bytes
        byte dlSettings,    // 1 byte
        byte rxDelay,       // 1 byte
        byte[] cfList,      // optional 16 bytes or null
        byte[] mic,         // 4 bytes
        byte[] rawEncrypted // encrypted bytes from wire
) {
    public String getJoinNonceHex() {
        return HexUtil.encodeHex(joinNonce);
    }

    public String getNetIdHex() {
        return HexUtil.encodeHex(netId);
    }

    public String getDevAddrHex() {
        return HexUtil.encodeHex(HexUtil.reverse(devAddr));
    }

    public String getMicHex() {
        return HexUtil.encodeHex(mic);
    }
}
