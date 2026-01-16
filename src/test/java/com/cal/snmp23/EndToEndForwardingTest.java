package com.cal.snmp23;

import com.cal.snmp23.config.ListenerConfig;
import com.cal.snmp23.config.SnmpV3Config;
import com.cal.snmp23.service.EngineStateManager;
import org.junit.jupiter.api.Test;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

class EndToEndForwardingTest {

    @Test
    void forwardV2cTrapAsV3() throws Exception {
        ListenerConfig listenerConfig = ListenerConfig.builder()
                .bindAddress("127.0.0.1")
                .listenPort(11162)
                .build();

        SnmpV3Config senderConfig = SnmpV3Config.builder()
                .targetHost("192.168.9.7")
                .targetPort(162)
                .username("AUTHENTICv3")
                .authPassword("Test1234!")
                .privPassword("Test1234!")
                .engineId("0x8000047304434b4d39383736353433323130")
                .authProtocol(SnmpV3Config.AuthProtocol.SHA)
                .privProtocol(SnmpV3Config.PrivProtocol.AES)
                .build();

        // 1. Initialize the manager to track state even during tests
        EngineStateManager stateManager = new EngineStateManager("engine-state-test.json");

        // 2. Get the incremented boot count for this specific engine ID
        int boots = stateManager.incrementAndGetBoots(senderConfig.engineId());

        SnmpForwarderApplication app = new SnmpForwarderApplication(listenerConfig, senderConfig);

        // 3. Pass the dynamic boot count instead of hardcoded 1
        app.start(boots);

        Thread.sleep(1000);
        sendTestTrap(11162);
        Thread.sleep(2000);

        app.stop();
    }

    private void sendTestTrap(int port) throws Exception {
        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        try {
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.2.1.1331.11.1.152.0")));
            pdu.add(new VariableBinding(
                    new OID("1.3.6.1.2.1.1331.11.1.152.1"),
                    new OctetString("TEST TRAP - BOOT COUNT CHECK")
            ));

            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("public"));
            target.setAddress(new UdpAddress("127.0.0.1/" + port));
            target.setVersion(SnmpConstants.version2c);

            snmp.send(pdu, target);
        } finally {
            snmp.close();
        }
    }
}