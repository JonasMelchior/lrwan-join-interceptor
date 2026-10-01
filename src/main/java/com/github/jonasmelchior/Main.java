package com.github.jonasmelchior;

import com.github.jonasmelchior.interceptor.JoinInterceptor;
import com.github.jonasmelchior.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        String brokerUrl = System.getProperty("mqtt.broker", "tcp://127.0.0.1:1883");
        String uplinkTopic = System.getProperty("mqtt.uplink.topic", "eu868/gateway/+/event/up");
        String downlinkTopic = System.getProperty("mqtt.downlink.topic", "eu868/gateway/+/command/down");

        // Target DevEUI and AppKey known to the adversary (cryptographically random realistic values)
        String targetDevEui = System.getProperty("dev.eui", System.getenv().getOrDefault("DEV_EUI", "07467874f27834b8"));
        String targetAppKeyHex = System.getProperty("app.key", System.getenv().getOrDefault("APP_KEY", "07dbdb82e850f8aa25e274d1632fa51b"));
        byte[] appKey = HexUtil.decodeHex(targetAppKeyHex);

        log.info("Starting LoRaWAN Join Interceptor Service...");
        log.info("Broker URL: {}", brokerUrl);
        log.info("Uplink Topic Filter: {}", uplinkTopic);
        log.info("Downlink Topic Filter: {}", downlinkTopic);
        log.info("Adversary Target DevEUI: {}", targetDevEui);
        log.info("Adversary Known AppKey: {}", HexUtil.encodeHex(appKey));

        JoinInterceptor interceptor = new JoinInterceptor(brokerUrl, uplinkTopic, downlinkTopic, targetDevEui, appKey);

        try {
            interceptor.start();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down interceptor...");
                interceptor.stop();
            }));

            Thread.currentThread().join();
        } catch (Exception e) {
            log.error("Fatal error running Join Interceptor: {}", e.getMessage(), e);
        }
    }
}
