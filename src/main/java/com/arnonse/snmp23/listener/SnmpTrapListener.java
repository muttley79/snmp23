package com.arnonse.snmp23.listener;

import com.arnonse.snmp23.config.ListenerConfig;
import com.arnonse.snmp23.model.TrapEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Listens for incoming SNMP v1 and v2c trap messages.
 */
public class SnmpTrapListener implements CommandResponder {
    private static final Logger logger = LoggerFactory.getLogger(SnmpTrapListener.class);

    private final ListenerConfig config;
    private final CopyOnWriteArrayList<Consumer<TrapEvent>> trapHandlers;
    private Snmp snmp;
    private TransportMapping<?> transportMapping;
    private boolean running = false;

    public SnmpTrapListener(ListenerConfig config) {
        this.config = config;
        this.trapHandlers = new CopyOnWriteArrayList<>();
    }

    /**
     * Registers a handler to be called when a trap is received.
     */
    public void registerTrapHandler(Consumer<TrapEvent> handler) {
        trapHandlers.add(handler);
        logger.info("Registered trap handler: {}", handler.getClass().getSimpleName());
    }

    /**
     * Starts listening for SNMP traps.
     */
    public void start() throws IOException {
        if (running) {
            logger.warn("Listener is already running");
            return;
        }

        logger.info("Starting SNMP trap listener on {}:{}", config.bindAddress(), config.listenPort());

        // Create UDP transport mapping
        Address listenAddress = GenericAddress.parse("udp:" + config.bindAddress() + "/" + config.listenPort());
        transportMapping = new DefaultUdpTransportMapping((UdpAddress) listenAddress);

        // Create thread pool for message dispatcher
        ThreadPool threadPool = ThreadPool.create("SnmpTrapListener", 4);
        MultiThreadedMessageDispatcher dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

        // Add support for SNMPv1 and SNMPv2c
        dispatcher.addMessageProcessingModel(new MPv1());
        dispatcher.addMessageProcessingModel(new MPv2c());

        // Create SNMP session
        snmp = new Snmp(dispatcher, transportMapping);
        snmp.addCommandResponder(this);

        // Start listening
        transportMapping.listen();
        running = true;

        logger.info("SNMP trap listener started successfully");
    }

    /**
     * Stops the listener.
     */
    public void stop() throws IOException {
        if (!running) {
            logger.warn("Listener is not running");
            return;
        }

        logger.info("Stopping SNMP trap listener");

        if (snmp != null) {
            snmp.close();
        }
        if (transportMapping != null) {
            transportMapping.close();
        }

        running = false;
        logger.info("SNMP trap listener stopped");
    }

    /**
     * Called when a trap/inform is received.
     */
    @Override
    public void processPdu(CommandResponderEvent event) {
        try {
            PDU pdu = event.getPDU();
            if (pdu == null) {
                logger.warn("Received null PDU");
                return;
            }

            Address sourceAddress = event.getPeerAddress();
            int snmpVersion = event.getMessageProcessingModel();
            String community = new String(event.getSecurityName());

            logger.info("Received trap from {} (SNMPv{}): {} variable bindings",
                    sourceAddress, snmpVersion + 1, pdu.size());

            // Create trap event
            TrapEvent trapEvent = new TrapEvent(sourceAddress, snmpVersion + 1, community, pdu);

            // Log variable bindings
            pdu.getVariableBindings().forEach(vb ->
                    logger.debug("  {} = {}", vb.getOid(), vb.getVariable())
            );

            // Notify all registered handlers
            for (Consumer<TrapEvent> handler : trapHandlers) {
                try {
                    handler.accept(trapEvent);
                } catch (Exception e) {
                    logger.error("Error in trap handler", e);
                }
            }

        } catch (Exception e) {
            logger.error("Error processing trap", e);
        }
    }

    public boolean isRunning() {
        return running;
    }

    public ListenerConfig getConfig() {
        return config;
    }
}
