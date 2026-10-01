package com.github.jonasmelchior;

import com.github.jonasmelchior.crypto.LoRaWanCrypto;
import com.github.jonasmelchior.model.JoinAcceptFrame;
import com.github.jonasmelchior.model.JoinRequestFrame;
import com.github.jonasmelchior.parser.LoRaWanParser;
import com.github.jonasmelchior.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class LoRaWanCryptoTest {

    @Test
    public void testJoinRequestAndAcceptFlow() throws Exception {
        byte[] appKey = HexUtil.decodeHex("00112233445566778899aabbccddeeff");
        byte[] joinEui = HexUtil.decodeHex("0102030405060708"); // 8 bytes
        byte[] devEui = HexUtil.decodeHex("1112131415161718");  // 8 bytes
        byte[] devNonce = HexUtil.decodeHex("abcd");            // 2 bytes

        // Build Join-Request
        byte[] reqMsg = new byte[19];
        reqMsg[0] = 0x00; // MHDR
        System.arraycopy(joinEui, 0, reqMsg, 1, 8);
        System.arraycopy(devEui, 0, reqMsg, 9, 8);
        System.arraycopy(devNonce, 0, reqMsg, 17, 2);

        byte[] reqMic = LoRaWanCrypto.calculateJoinRequestMic(appKey, reqMsg);
        assertEquals(4, reqMic.length);

        byte[] fullReqPhy = new byte[23];
        System.arraycopy(reqMsg, 0, fullReqPhy, 0, 19);
        System.arraycopy(reqMic, 0, fullReqPhy, 19, 4);

        // Test parser
        JoinRequestFrame parsedReq = LoRaWanParser.parseJoinRequest(fullReqPhy, appKey);
        assertNotNull(parsedReq);
        assertArrayEquals(devNonce, parsedReq.devNonce());

        // Build Join-Accept
        byte jaMhdr = 0x20;
        byte[] joinNonce = HexUtil.decodeHex("123456");
        byte[] netId = HexUtil.decodeHex("000000");
        byte[] devAddr = HexUtil.decodeHex("01020304");
        byte dlSettings = 0x00;
        byte rxDelay = 0x01;

        byte[] jaMacPayload = new byte[12];
        System.arraycopy(joinNonce, 0, jaMacPayload, 0, 3);
        System.arraycopy(netId, 0, jaMacPayload, 3, 3);
        System.arraycopy(devAddr, 0, jaMacPayload, 6, 4);
        jaMacPayload[10] = dlSettings;
        jaMacPayload[11] = rxDelay;

        byte[] jaMic = LoRaWanCrypto.calculateJoinAcceptMic(appKey, jaMhdr, jaMacPayload);
        assertEquals(4, jaMic.length);

        // Encrypt with AES-128 decrypt (standard server side)
        byte[] unencrypted = new byte[16];
        System.arraycopy(jaMacPayload, 0, unencrypted, 0, 12);
        System.arraycopy(jaMic, 0, unencrypted, 12, 4);

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(appKey, "AES"));
        byte[] encryptedPayload = cipher.doFinal(unencrypted);

        byte[] fullJaPhy = new byte[17];
        fullJaPhy[0] = jaMhdr;
        System.arraycopy(encryptedPayload, 0, fullJaPhy, 1, 16);

        // Test Join-Accept parser
        JoinAcceptFrame parsedJa = LoRaWanParser.parseJoinAccept(fullJaPhy, appKey);
        assertNotNull(parsedJa);
        assertArrayEquals(joinNonce, parsedJa.joinNonce());
        assertArrayEquals(netId, parsedJa.netId());

        // Test Session key derivation
        byte[] nwkSKey = LoRaWanCrypto.deriveNwkSKey(appKey, joinNonce, netId, devNonce);
        byte[] appSKey = LoRaWanCrypto.deriveAppSKey(appKey, joinNonce, netId, devNonce);
        assertEquals(16, nwkSKey.length);
        assertEquals(16, appSKey.length);
    }
}
