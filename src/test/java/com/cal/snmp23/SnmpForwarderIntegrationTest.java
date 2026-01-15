package com.cal.snmp23;

import com.cal.snmp23.config.ListenerConfig;
import com.cal.snmp23.config.SnmpV3Config;
import com.cal.snmp23.listener.SnmpTrapListener;
import com.cal.snmp23.model.TrapEvent;
import com.cal.snmp23.sender.SnmpV3TrapSender;
import org.junit.jupiter.api.*;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.TransportMapping;
import org.snmp4j.CommunityTarget;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;


import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for SNMP trap forwarding.
 * Note: These tests use non-privileged ports (>1024) to avoid permission issues.
 */
class SnmpForwarderIntegrationTest {

    private static final int TEST_LISTEN_PORT = 11162;
    private static final String TEST_TARGET_HOST = "192.168.9.7";
    private static final String TEST_ENGINE_ID = "0x8000047304434b4d39383736353433323130";

    private SnmpTrapListener listener;

    @BeforeEach
    void setUp() {
        ListenerConfig config = ListenerConfig.builder()
                .bindAddress("127.0.0.1")
                .listenPort(TEST_LISTEN_PORT)
                .build();

        listener = new SnmpTrapListener(config);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (listener != null && listener.isRunning()) {
            listener.stop();
        }
    }

    @Test
    @DisplayName("Should receive and process SNMPv2c trap")
    void testReceiveV2cTrap() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<TrapEvent> receivedEvent = new AtomicReference<>();

        // Register handler
        listener.registerTrapHandler(event -> {
            receivedEvent.set(event);
            latch.countDown();
        });

        // Start listener
        listener.start();

        // Wait for listener to be ready
        Thread.sleep(500);

        // Send test trap
        sendTestTrap();

        // Wait for trap to be received
        boolean received = latch.await(5, TimeUnit.SECONDS);

        assertTrue(received, "Trap should be received within timeout");
        assertNotNull(receivedEvent.get());
        assertEquals(2, receivedEvent.get().getSnmpVersion());
        assertTrue(receivedEvent.get().getVariableBindings().size() > 0);
    }

    @Test
    @DisplayName("Should handle multiple traps")
    void testMultipleTraps() throws Exception {
        CountDownLatch latch = new CountDownLatch(3);

        listener.registerTrapHandler(event -> latch.countDown());
        listener.start();

        Thread.sleep(500);

        // Send multiple traps
        for (int i = 0; i < 3; i++) {
            sendTestTrap();
            Thread.sleep(100);
        }

        boolean received = latch.await(10, TimeUnit.SECONDS);
        assertTrue(received, "All traps should be received");
    }

    @Test
    @DisplayName("Configuration validation for SnmpV3Config")
    void testSnmpV3ConfigValidation() {
        SnmpV3Config config = SnmpV3Config.builder()
                .targetHost(TEST_TARGET_HOST)
                .targetPort(162)
                .username("testUser")
                .authPassword("testAuthPass")
                .privPassword("testPrivPass")
                .engineId(TEST_ENGINE_ID)
                .authProtocol(SnmpV3Config.AuthProtocol.SHA)
                .privProtocol(SnmpV3Config.PrivProtocol.AES)
                .build();

        assertNotNull(config);
        assertEquals(TEST_TARGET_HOST, config.targetHost());
        assertEquals("testUser", config.username());
    }

    @Test
    @DisplayName("Listener should start and stop cleanly")
    void testListenerLifecycle() throws IOException {
        assertFalse(listener.isRunning());

        listener.start();
        assertTrue(listener.isRunning());

        listener.stop();
        assertFalse(listener.isRunning());
    }

    @Test
    @DisplayName("Should handle trap with custom OID")
    void testTrapWithCustomOid() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<TrapEvent> receivedEvent = new AtomicReference<>();

        listener.registerTrapHandler(event -> {
            receivedEvent.set(event);
            latch.countDown();
        });

        listener.start();
        Thread.sleep(500);

        // Send trap with custom OID
        sendTrapWithCustomOid("1.3.6.1.2.1.1331.11.1.152.0");

        boolean received = latch.await(5, TimeUnit.SECONDS);

        assertTrue(received);
        assertNotNull(receivedEvent.get());
        
        // Verify custom OID is in variable bindings
        boolean foundOid = receivedEvent.get().getVariableBindings().stream()
                .anyMatch(vb -> vb.getOid().toString().contains("1.3.6.1.2.1.1331"));
        
        assertTrue(foundOid, "Custom OID should be present in trap");
    }

    /**
     * Helper method to send a test trap to the listener.
     */
    private void sendTestTrap() throws IOException {
        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        try {
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.6.3.1.1.5.3")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0"), new OctetString("Test Trap")));

            Target target = new CommunityTarget();
            target.setAddress(new UdpAddress("127.0.0.1/" + TEST_LISTEN_PORT));
            target.setVersion(SnmpConstants.version2c);
            target.setTimeout(1000);
            target.setRetries(0);

            snmp.send(pdu, target);
        } finally {
            snmp.close();
        }
    }

    /**
     * Helper method to send a trap with a custom OID.
     */
    private void sendTrapWithCustomOid(String customOid) throws IOException {
        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        try {
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(customOid)));
            pdu.add(new VariableBinding(
                    new OID("1.3.6.1.2.1.1331.11.1.152.1"),
                    new OctetString("MACHINE:test; EVENT:TEST_EVENT; CATEGORY:SYSTEM-INFO")
            ));

            Target target = new CommunityTarget();
            target.setAddress(new UdpAddress("127.0.0.1/" + TEST_LISTEN_PORT));
            target.setVersion(SnmpConstants.version2c);
            target.setTimeout(1000);
            target.setRetries(0);

            snmp.send(pdu, target);
        } finally {
            snmp.close();
        }
    }
}
