package com.github.jonasmelchior.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * Utility class for LoRaWAN 1.0.x cryptographic operations:
 * - Join-Request MIC calculation & verification
 * - Join-Accept Payload decryption (via AES-128 Encrypt in ECB mode)
 * - Join-Accept MIC calculation & verification
 * - Session Key derivation (NwkSKey and AppSKey)
 */
public class LoRaWanCrypto {

    /**
     * Computes or verifies Join-Request MIC.
     * Join-Request MIC = AES128_CMAC(AppKey, MHDR | JoinEUI | DevEUI | DevNonce)[0..3]
     *
     * @param appKey 16-byte root key
     * @param mhdrAndMacPayload bytes of (MHDR | JoinEUI | DevEUI | DevNonce), total 19 bytes
     * @return 4-byte MIC
     */
    public static byte[] calculateJoinRequestMic(byte[] appKey, byte[] mhdrAndMacPayload) {
        return calculateAesCmac(appKey, mhdrAndMacPayload, 4);
    }

    /**
     * Decrypts a Join-Accept encrypted payload according to LoRaWAN 1.0.x specification.
     * In LoRaWAN specification, the network server encrypts the Join-Accept using AES-128 decrypt.
     * Therefore, to recover the plaintext MACPayload and MIC, the device/interceptor applies AES-128 encrypt.
     *
     * @param appKey 16-byte AppKey
     * @param encryptedPayload Join-Accept payload (excluding the 1-byte MHDR), usually 16 or 32 bytes
     * @return decrypted bytes (MACPayload | MIC)
     */
    public static byte[] decryptJoinAccept(byte[] appKey, byte[] encryptedPayload) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(appKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedPayload);
    }

    /**
     * Calculates the Join-Accept MIC over MHDR | decrypted MACPayload.
     * Join-Accept MIC = AES128_CMAC(AppKey, MHDR | MACPayload)[0..3]
     *
     * @param appKey 16-byte AppKey
     * @param mhdr single byte MHDR (0x20)
     * @param macPayload decrypted MACPayload (JoinNonce | NetID | DevAddr | DLSettings | RxDelay | [CFList])
     * @return 4-byte calculated MIC
     */
    public static byte[] calculateJoinAcceptMic(byte[] appKey, byte mhdr, byte[] macPayload) {
        byte[] data = new byte[1 + macPayload.length];
        data[0] = mhdr;
        System.arraycopy(macPayload, 0, data, 1, macPayload.length);
        return calculateAesCmac(appKey, data, 4);
    }

    /**
     * Derives Network Session Key (NwkSKey) for LoRaWAN 1.0.x:
     * NwkSKey = AES128_Encrypt(AppKey, 0x01 | JoinNonce (3B) | NetID (3B) | DevNonce (2B) | pad16 (7B 0x00))
     */
    public static byte[] deriveNwkSKey(byte[] appKey, byte[] joinNonce, byte[] netId, byte[] devNonce) throws Exception {
        return deriveSessionKey((byte) 0x01, appKey, joinNonce, netId, devNonce);
    }

    /**
     * Derives Application Session Key (AppSKey) for LoRaWAN 1.0.x:
     * AppSKey = AES128_Encrypt(AppKey, 0x02 | JoinNonce (3B) | NetID (3B) | DevNonce (2B) | pad16 (7B 0x00))
     */
    public static byte[] deriveAppSKey(byte[] appKey, byte[] joinNonce, byte[] netId, byte[] devNonce) throws Exception {
        return deriveSessionKey((byte) 0x02, appKey, joinNonce, netId, devNonce);
    }

    private static byte[] deriveSessionKey(byte keyType, byte[] appKey, byte[] joinNonce, byte[] netId, byte[] devNonce) throws Exception {
        byte[] b = new byte[16];
        b[0] = keyType;
        System.arraycopy(joinNonce, 0, b, 1, 3);
        System.arraycopy(netId, 0, b, 4, 3);
        System.arraycopy(devNonce, 0, b, 7, 2);
        // remaining 7 bytes (b[9..15]) are zero-padded

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(appKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(b);
    }

    /**
     * Helper to compute AES-CMAC using Bouncy Castle.
     */
    public static byte[] calculateAesCmac(byte[] key, byte[] data, int length) {
        BlockCipher cipher = AESEngine.newInstance();
        CMac cmac = new CMac(cipher);
        cmac.init(new KeyParameter(key));
        cmac.update(data, 0, data.length);
        byte[] output = new byte[cmac.getMacSize()];
        cmac.doFinal(output, 0);
        return Arrays.copyOfRange(output, 0, length);
    }
}
