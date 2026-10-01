package com.github.jonasmelchior.parser;

import com.github.jonasmelchior.crypto.LoRaWanCrypto;
import com.github.jonasmelchior.model.JoinAcceptFrame;
import com.github.jonasmelchior.model.JoinRequestFrame;
import com.github.jonasmelchior.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Parser for LoRaWAN over-the-air PHYPayload bytes.
 */
public class LoRaWanParser {
    private static final Logger log = LoggerFactory.getLogger(LoRaWanParser.class);

    public static final byte MTYPE_JOIN_REQUEST = (byte) 0x00;
    public static final byte MTYPE_JOIN_ACCEPT = (byte) 0x20;

    /**
     * Parses and optionally validates a Join-Request PHYPayload.
     * Expected format:
     * - MHDR (1 byte): 0x00 (Join-Request)
     * - JoinEUI / AppEUI (8 bytes)
     * - DevEUI (8 bytes)
     * - DevNonce (2 bytes)
     * - MIC (4 bytes)
     * Total = 23 bytes
     */
    public static JoinRequestFrame parseJoinRequest(byte[] phyPayload, byte[] knownAppKey) {
        if (phyPayload == null || phyPayload.length != 23) {
            return null;
        }

        byte mhdr = phyPayload[0];
        // Check MType (bits 7-5). 000 = Join-Request (0x00)
        if ((mhdr & 0xE0) != 0x00) {
            return null;
        }

        byte[] joinEui = Arrays.copyOfRange(phyPayload, 1, 9);
        byte[] devEui = Arrays.copyOfRange(phyPayload, 9, 17);
        byte[] devNonce = Arrays.copyOfRange(phyPayload, 17, 19);
        byte[] mic = Arrays.copyOfRange(phyPayload, 19, 23);

        if (knownAppKey != null) {
            byte[] msg = Arrays.copyOfRange(phyPayload, 0, 19);
            byte[] calculatedMic = LoRaWanCrypto.calculateJoinRequestMic(knownAppKey, msg);
            if (!Arrays.equals(mic, calculatedMic)) {
                log.debug("[Step 1] Join-Request MIC check failed for candidate key. Expected: {}, Got: {}",
                        HexUtil.encodeHex(calculatedMic), HexUtil.encodeHex(mic));
                return null;
            }
        }

        return new JoinRequestFrame(mhdr, joinEui, devEui, devNonce, mic, phyPayload);
    }

    /**
     * Attempts to parse, decrypt, and validate a Join-Accept PHYPayload using known AppKey.
     * Expected format:
     * - MHDR (1 byte): 0x20 (Join-Accept)
     * - Encrypted payload (16 or 32 bytes, depending on CFList presence)
     * Total = 17 or 33 bytes.
     */
    public static JoinAcceptFrame parseJoinAccept(byte[] phyPayload, byte[] appKey) {
        if (phyPayload == null || (phyPayload.length != 17 && phyPayload.length != 33)) {
            return null;
        }

        byte mhdr = phyPayload[0];
        // Check MType (bits 7-5). 001 = Join-Accept (0x20)
        if ((mhdr & 0xE0) != 0x20) {
            return null;
        }

        byte[] encryptedPayload = Arrays.copyOfRange(phyPayload, 1, phyPayload.length);

        try {
            // Decrypt using AES-128 encrypt
            byte[] decrypted = LoRaWanCrypto.decryptJoinAccept(appKey, encryptedPayload);

            // Decrypted structure:
            // JoinNonce (3B) | NetID (3B) | DevAddr (4B) | DLSettings (1B) | RxDelay (1B) | [CFList (16B)] | MIC (4B)
            int micOffset = decrypted.length - 4;
            byte[] macPayload = Arrays.copyOfRange(decrypted, 0, micOffset);
            byte[] mic = Arrays.copyOfRange(decrypted, micOffset, decrypted.length);

            // Validate Join-Accept MIC
            byte[] calculatedMic = LoRaWanCrypto.calculateJoinAcceptMic(appKey, mhdr, macPayload);
            if (!Arrays.equals(mic, calculatedMic)) {
                log.debug("[Step 2] Join-Accept candidate MIC mismatch. Expected: {}, Got: {}",
                        HexUtil.encodeHex(calculatedMic), HexUtil.encodeHex(mic));
                return null;
            }

            // Extract fields
            byte[] joinNonce = Arrays.copyOfRange(macPayload, 0, 3);
            byte[] netId = Arrays.copyOfRange(macPayload, 3, 6);
            byte[] devAddr = Arrays.copyOfRange(macPayload, 6, 10);
            byte dlSettings = macPayload[10];
            byte rxDelay = macPayload[11];
            byte[] cfList = null;
            if (macPayload.length > 12) {
                cfList = Arrays.copyOfRange(macPayload, 12, macPayload.length);
            }

            return new JoinAcceptFrame(mhdr, joinNonce, netId, devAddr, dlSettings, rxDelay, cfList, mic, encryptedPayload);
        } catch (Exception e) {
            log.debug("[Step 2] Error decrypting or parsing Join-Accept: {}", e.getMessage());
            return null;
        }
    }
}
