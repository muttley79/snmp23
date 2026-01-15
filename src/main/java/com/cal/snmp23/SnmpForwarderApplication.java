package com.cal.snmp23;

import com.cal.snmp23.config.ListenerConfig;
import com.cal.snmp23.config.SnmpV3Config;
import com.cal.snmp23.listener.SnmpTrapListener;
import com.cal.snmp23.sender.SnmpV3TrapSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Main application that forwards SNMP v1/v2c traps to SNMPv3.
 */
public class SnmpForwarderApplication {
    private static final Logger logger = LoggerFactory.getLogger(SnmpForwarderApplication.class);

    private final SnmpTrapListener listener;
    private final SnmpV3TrapSender sender;

    public SnmpForwarderApplication(ListenerConfig listenerConfig, SnmpV3Config senderConfig) {
        this.listener = new SnmpTrapListener(listenerConfig);
        this.sender = new SnmpV3TrapSender(senderConfig);
    }

    /**
     * Starts the forwarder application.
     */
    public void start() throws IOException {
        logger.info("Starting SNMP Trap Forwarder");

        // Initialize sender
        sender.initialize();

        // Register trap handler to forward received traps
        listener.registerTrapHandler(trapEvent -> {
            logger.info("Received trap event: {}", trapEvent);
            sender.sendTrap(trapEvent);
        });

        // Start listener
        listener.start();

        logger.info("SNMP Trap Forwarder started successfully");
    }

    /**
     * Stops the forwarder application.
     */
    public void stop() throws IOException {
        logger.info("Stopping SNMP Trap Forwarder");

        listener.stop();
        sender.close();

        logger.info("SNMP Trap Forwarder stopped");
    }

    /**
     * Main entry point.
     */
    public static void main(String[] args) {
        try {
            // Configuration - in production, load from config file or environment
            ListenerConfig listenerConfig = ListenerConfig.builder()
                    .bindAddress("0.0.0.0")
                    .listenPort(1162)  // Use non-privileged port for testing
                    .build();

            SnmpV3Config senderConfig = SnmpV3Config.builder()
                    .targetHost("192.168.9.202")
                    .targetPort(162)
                    .username("AUTHENTICv3")
                    .authPassword("Test1234!")
                    .privPassword("Test1234!")
                    .engineId("0x8000047304434b4d39383736353433323130")
                    .authProtocol(SnmpV3Config.AuthProtocol.SHA)
                    .privProtocol(SnmpV3Config.PrivProtocol.AES)
                    .build();

            SnmpForwarderApplication app = new SnmpForwarderApplication(listenerConfig, senderConfig);

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    app.stop();
                } catch (IOException e) {
                    logger.error("Error during shutdown", e);
                }
            }));

            // Start application
            app.start();

            logger.info("SNMP Trap Forwarder is running. Press Ctrl+C to stop.");

            // Keep application running
            Thread.currentThread().join();

        } catch (Exception e) {
            logger.error("Fatal error in SNMP Trap Forwarder", e);
            System.exit(1);
        }
    }
}
