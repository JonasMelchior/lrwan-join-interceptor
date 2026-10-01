package com.github.jonasmelchior.model;

import com.github.jonasmelchior.util.HexUtil;

public record DerivedSessionKeys(
        String devEuiHex,
        byte[] devNonce,
        byte[] joinNonce,
        byte[] netId,
        byte[] nwkSKey,
        byte[] appSKey
) {
    public String getNwkSKeyHex() {
        return HexUtil.encodeHex(nwkSKey);
    }

    public String getAppSKeyHex() {
        return HexUtil.encodeHex(appSKey);
    }
}
