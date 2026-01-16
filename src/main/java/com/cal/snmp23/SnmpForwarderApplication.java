package com.cal.snmp23;

import com.cal.snmp23.config.ListenerConfig;
import com.cal.snmp23.config.SnmpV3Config;
import com.cal.snmp23.listener.SnmpTrapListener;
import com.cal.snmp23.sender.SnmpV3TrapSender;
import com.cal.snmp23.service.EngineStateManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class SnmpForwarderApplication {
    private static final Logger logger = LoggerFactory.getLogger(SnmpForwarderApplication.class);

    private final SnmpTrapListener listener;
    private final SnmpV3TrapSender sender;

    public SnmpForwarderApplication(ListenerConfig listenerConfig, SnmpV3Config senderConfig) {
        this.listener = new SnmpTrapListener(listenerConfig);
        this.sender = new SnmpV3TrapSender(senderConfig);
    }

    public void start(int bootCount) throws IOException {
        logger.info("Starting SNMP Trap Forwarder");

        sender.initialize(bootCount);

        listener.registerTrapHandler(trapEvent -> {
            logger.info("Received trap event: {}", trapEvent);
            sender.sendTrap(trapEvent);
        });

        listener.start();
        logger.info("SNMP Trap Forwarder started successfully");
    }

    public void stop() throws IOException {
        listener.stop();
        sender.close();
    }

    public static void main(String[] args) {
        Properties props = new Properties();
        String configPath = (args.length > 0) ? args[0] : "application.properties";
        try (InputStream input = new FileInputStream(configPath)) {
            props.load(input);

            ListenerConfig listenerConfig = ListenerConfig.builder()
                    .bindAddress(props.getProperty("listener.bindAddress", "0.0.0.0"))
                    .listenPort(Integer.parseInt(props.getProperty("listener.port", "1162")))
                    .build();

            SnmpV3Config senderConfig = SnmpV3Config.builder()
                    .targetHost(props.getProperty("v3.targetHost"))
                    .targetPort(Integer.parseInt(props.getProperty("v3.targetPort", "162")))
                    .username(props.getProperty("v3.username"))
                    .authPassword(props.getProperty("v3.authPassword"))
                    .privPassword(props.getProperty("v3.privPassword"))
                    .engineId(props.getProperty("v3.engineId"))
                    .authProtocol(SnmpV3Config.AuthProtocol.valueOf(props.getProperty("v3.authProtocol", "SHA")))
                    .privProtocol(SnmpV3Config.PrivProtocol.valueOf(props.getProperty("v3.privProtocol", "AES")))
                    .build();

            EngineStateManager stateManager = new EngineStateManager(props.getProperty("state.file", "engine-state.json"));
            int boots = stateManager.incrementAndGetBoots(senderConfig.engineId());

            SnmpForwarderApplication app = new SnmpForwarderApplication(listenerConfig, senderConfig);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { app.stop(); } catch (IOException e) { logger.error("Shutdown error", e); }
            }));

            app.start(boots);
            Thread.currentThread().join();

        } catch (Exception e) {
            logger.error("Fatal error", e);
            System.exit(1);
        }
    }
}