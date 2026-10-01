package com.github.jonasmelchior.interceptor;

import com.github.jonasmelchior.crypto.LoRaWanCrypto;
import com.github.jonasmelchior.model.DerivedSessionKeys;
import com.github.jonasmelchior.model.JoinAcceptFrame;
import com.github.jonasmelchior.model.JoinRequestFrame;
import com.github.jonasmelchior.parser.LoRaWanParser;
import com.github.jonasmelchior.util.HexUtil;
import io.chirpstack.api.gw.DownlinkFrame;
import io.chirpstack.api.gw.DownlinkFrameItem;
import io.chirpstack.api.gw.UplinkFrame;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttCallback;
import org.eclipse.paho.mqttv5.client.MqttClient;
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions;
import org.eclipse.paho.mqttv5.client.MqttDisconnectResponse;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * LoRaWAN Join Interceptor.
 * Simulates over-the-air packet interception over ChirpStack simulated gateway MQTT link:
 * - Adversary is in possession of target DevEUI and corresponding root AppKey (or a map of DevEUI -> AppKey).
 * - Step 1: Intercepts Uplink Join-Request, filters for target DevEUI, validates MIC using target AppKey, stores collected DevNonce.
 * - Step 2: Intercepts Downlink Join-Accept, validates MIC using target AppKey, collects JoinNonce and NetID.
 * - Step 3: Derives LoRaWAN 1.0.x session keys (NwkSKey & AppSKey).
 */
public class JoinInterceptor implements MqttCallback {
    private static final Logger log = LoggerFactory.getLogger(JoinInterceptor.class);

    private final String brokerUrl;
    private final String uplinkTopicFilter;
    private final String downlinkTopicFilter;
    
    // Map of known target DevEUI (hex lowercase) -> known AppKey (16 bytes)
    private final Map<String, byte[]> knownDevices = new ConcurrentHashMap<>();

    // Track pending join requests by DevEUI hex string
    private final Map<String, JoinRequestFrame> pendingJoinRequests = new ConcurrentHashMap<>();

    // Track successfully derived session keys by DevEUI
    private final Map<String, DerivedSessionKeys> derivedKeys = new ConcurrentHashMap<>();

    private MqttClient mqttClient;

    public JoinInterceptor(String brokerUrl, String uplinkTopicFilter, String downlinkTopicFilter, String targetDevEuiHex, byte[] appKey) {
        this.brokerUrl = brokerUrl;
        this.uplinkTopicFilter = uplinkTopicFilter;
        this.downlinkTopicFilter = downlinkTopicFilter;
        if (targetDevEuiHex != null && !targetDevEuiHex.isBlank()) {
            this.knownDevices.put(targetDevEuiHex.toLowerCase(), appKey);
        }
    }

    public JoinInterceptor(String brokerUrl, String uplinkTopicFilter, String downlinkTopicFilter, Map<String, byte[]> knownDevices) {
        this.brokerUrl = brokerUrl;
        this.uplinkTopicFilter = uplinkTopicFilter;
        this.downlinkTopicFilter = downlinkTopicFilter;
        this.knownDevices.putAll(knownDevices);
    }

    public void addTargetDevice(String devEuiHex, byte[] appKey) {
        knownDevices.put(devEuiHex.toLowerCase(), appKey);
        log.info("[Config] Registered target DevEUI: {} with AppKey: {}", devEuiHex.toLowerCase(), HexUtil.encodeHex(appKey));
    }

    public void start() throws MqttException {
        log.info("================================================================================");
        log.info("  Starting LoRaWAN 1.0.x Join Interceptor");
        log.info("  Target Broker: {}", brokerUrl);
        log.info("  Configured Target Devices:");
        for (Map.Entry<String, byte[]> entry : knownDevices.entrySet()) {
            log.info("    -> Target DevEUI: {} | AppKey: {}", entry.getKey(), HexUtil.encodeHex(entry.getValue()));
        }
        log.info("  Listening OTA Links -> Uplinks: [{}], Downlinks: [{}]", uplinkTopicFilter, downlinkTopicFilter);
        log.info("================================================================================");

        String clientId = "lorawan-join-interceptor-" + System.currentTimeMillis();
        mqttClient = new MqttClient(brokerUrl, clientId, null);
        mqttClient.setCallback(this);

        MqttConnectionOptions options = new MqttConnectionOptions();
        options.setCleanStart(true);
        options.setAutomaticReconnect(true);

        log.info("[Connection] Connecting to MQTT broker at {} ...", brokerUrl);
        mqttClient.connect(options);
        log.info("[Connection] Successfully connected to MQTT broker.");

        mqttClient.subscribe(new String[]{uplinkTopicFilter, downlinkTopicFilter}, new int[]{0, 0});
        log.info("[OTA Link] Subscribed to OTA gateway topics. Waiting for LoRaWAN join procedures...");
    }

    public void stop() {
        if (mqttClient != null && mqttClient.isConnected()) {
            try {
                mqttClient.disconnect();
                mqttClient.close();
                log.info("[Shutdown] LoRaWAN Join Interceptor stopped.");
            } catch (MqttException e) {
                log.error("[Shutdown] Error stopping MQTT client: {}", e.getMessage());
            }
        }
    }

    public Map<String, DerivedSessionKeys> getDerivedKeys() {
        return derivedKeys;
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) {
        byte[] payload = message.getPayload();
        try {
            if (topic.endsWith("/event/up")) {
                handleUplink(topic, payload);
            } else if (topic.endsWith("/command/down")) {
                handleDownlink(topic, payload);
            }
        } catch (Exception e) {
            log.error("[Error] Error processing message on topic {}: {}", topic, e.getMessage(), e);
        }
    }

    private void handleUplink(String topic, byte[] payload) {
        try {
            UplinkFrame uplinkFrame = UplinkFrame.parseFrom(payload);
            byte[] phyBytes = uplinkFrame.getPhyPayload().toByteArray();

            if (phyBytes.length != 23 || (phyBytes[0] & 0xE0) != 0x00) {
                // Not a Join-Request
                return;
            }

            // Quick extraction of DevEUI from raw frame before MIC check
            // DevEUI is bytes 9..17 (little endian in frame)
            byte[] devEuiBytes = java.util.Arrays.copyOfRange(phyBytes, 9, 17);
            String devEuiHex = HexUtil.encodeHex(HexUtil.reverse(devEuiBytes)).toLowerCase();

            byte[] appKey = knownDevices.get(devEuiHex);
            if (appKey == null) {
                // Not one of our targeted DevEUIs
                log.debug("[Step 1 - Intercept Join-Request] Intercepted Join-Request for non-target DevEUI: {}. Skipping.", devEuiHex);
                return;
            }

            log.info("[Step 1 - Intercept Join-Request] Intercepted OTA Uplink Join-Request for target DevEUI: {} on topic '{}'",
                    devEuiHex, topic);

            JoinRequestFrame req = LoRaWanParser.parseJoinRequest(phyBytes, appKey);
            if (req != null) {
                log.info("[Step 1 - Parsed Join-Request] Valid MIC verified using target AppKey! DevEUI: {}, JoinEUI: {}, DevNonce: {}, MIC: {}",
                        devEuiHex, req.getJoinEuiHex(), req.getDevNonceHex(), req.getMicHex());

                pendingJoinRequests.put(devEuiHex, req);
                log.info("[Step 1 - State Saved] Saved pending Join-Request for DevEUI {} (DevNonce: {}). Waiting for matching Join-Accept...",
                        devEuiHex, req.getDevNonceHex());
            } else {
                log.warn("[Step 1 - MIC Failure] Join-Request MIC validation failed for DevEUI {} with configured AppKey {}.",
                        devEuiHex, HexUtil.encodeHex(appKey));
            }
        } catch (Exception e) {
            log.debug("[Step 1] Uplink frame parse error: {}", e.getMessage());
        }
    }

    private void handleDownlink(String topic, byte[] payload) {
        try {
            DownlinkFrame downlinkFrame = DownlinkFrame.parseFrom(payload);
            for (DownlinkFrameItem item : downlinkFrame.getItemsList()) {
                byte[] phyBytes = item.getPhyPayload().toByteArray();
                if ((phyBytes.length != 17 && phyBytes.length != 33) || (phyBytes[0] & 0xE0) != 0x20) {
                    // Not a Join-Accept
                    continue;
                }

                log.info("[Step 2 - Intercept Join-Accept] Intercepted OTA Downlink Join-Accept frame on topic '{}' (raw len: {} B)",
                        topic, phyBytes.length);

                if (pendingJoinRequests.isEmpty()) {
                    log.debug("[Step 2 - Notice] Received Join-Accept candidate, but no pending Join-Requests in interceptor cache.");
                    continue;
                }

                // Check against each pending target device's AppKey
                for (Map.Entry<String, JoinRequestFrame> entry : pendingJoinRequests.entrySet()) {
                    String devEuiHex = entry.getKey();
                    JoinRequestFrame req = entry.getValue();
                    byte[] appKey = knownDevices.get(devEuiHex);
                    if (appKey == null) continue;

                    JoinAcceptFrame acceptFrame = LoRaWanParser.parseJoinAccept(phyBytes, appKey);
                    if (acceptFrame != null) {
                        log.info("[Step 2 - Parsed Join-Accept] MIC verified successfully for DevEUI {}! JoinNonce: {}, NetID: {}, DevAddr: {}, MIC: {}",
                                devEuiHex, acceptFrame.getJoinNonceHex(), acceptFrame.getNetIdHex(), acceptFrame.getDevAddrHex(), acceptFrame.getMicHex());

                        log.info("[Step 3 - Key Derivation] Deriving session keys for DevEUI {} using AppKey, DevNonce: {}, JoinNonce: {}, NetID: {}...",
                                devEuiHex, req.getDevNonceHex(), acceptFrame.getJoinNonceHex(), acceptFrame.getNetIdHex());

                        try {
                            byte[] nwkSKey = LoRaWanCrypto.deriveNwkSKey(
                                    appKey,
                                    acceptFrame.joinNonce(),
                                    acceptFrame.netId(),
                                    req.devNonce()
                            );
                            byte[] appSKey = LoRaWanCrypto.deriveAppSKey(
                                    appKey,
                                    acceptFrame.joinNonce(),
                                    acceptFrame.netId(),
                                    req.devNonce()
                            );

                            DerivedSessionKeys keys = new DerivedSessionKeys(
                                    devEuiHex,
                                    req.devNonce(),
                                    acceptFrame.joinNonce(),
                                    acceptFrame.netId(),
                                    nwkSKey,
                                    appSKey
                            );

                            derivedKeys.put(devEuiHex, keys);
                            // Once activated, remove pending request so we don't re-process duplicate items
                            pendingJoinRequests.remove(devEuiHex);

                            log.info("================================================================================");
                            log.info("  [SUCCESS] LoRaWAN 1.0.x Session Keys Derived Successfully!");
                            log.info("  Device DevEUI : {}", devEuiHex);
                            log.info("  Device DevAddr: {}", acceptFrame.getDevAddrHex());
                            log.info("  DevNonce      : {}", req.getDevNonceHex());
                            log.info("  JoinNonce     : {}", acceptFrame.getJoinNonceHex());
                            log.info("  Home NetID    : {}", acceptFrame.getNetIdHex());
                            log.info("  >> Derived NwkSKey: {}", keys.getNwkSKeyHex());
                            log.info("  >> Derived AppSKey: {}", keys.getAppSKeyHex());
                            log.info("================================================================================");
                            return; // Finished processing this downlink frame
                        } catch (Exception e) {
                            log.error("[Step 3 - Error] Failed to derive session keys for DevEUI {}: {}", devEuiHex, e.getMessage(), e);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[Step 2] Downlink frame parse error: {}", e.getMessage());
        }
    }

    @Override
    public void disconnected(MqttDisconnectResponse disconnectResponse) {
        log.warn("[Connection] MQTT disconnected: {}", disconnectResponse.getReasonString());
    }

    @Override
    public void mqttErrorOccurred(MqttException exception) {
        log.error("[Connection] MQTT error occurred: {}", exception.getMessage());
    }

    @Override
    public void deliveryComplete(IMqttToken token) {
    }

    @Override
    public void connectComplete(boolean reconnect, String serverURI) {
        log.info("[Connection] MQTT connect complete. Reconnect = {}", reconnect);
        if (reconnect) {
            try {
                mqttClient.subscribe(new String[]{uplinkTopicFilter, downlinkTopicFilter}, new int[]{0, 0});
                log.info("[OTA Link] Resubscribed to OTA gateway topics after reconnect.");
            } catch (MqttException e) {
                log.error("[Connection] Error resubscribing after reconnect: {}", e.getMessage());
            }
        }
    }

    @Override
    public void authPacketArrived(int reasonCode, MqttProperties properties) {
    }
}
