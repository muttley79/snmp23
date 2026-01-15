package com.cal.snmp23.model;

import org.junit.jupiter.api.Test;
import org.snmp4j.PDU;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class TrapEventTest {

    @Test
    void testTrapEventCreation() {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0"), new OctetString("test")));

        TrapEvent event = new TrapEvent(sourceAddress, 2, "public", pdu);

        assertNotNull(event);
        assertEquals(sourceAddress, event.getSourceAddress());
        assertEquals(2, event.getSnmpVersion());
        assertEquals("public", event.getCommunity());
        assertNotNull(event.getReceivedAt());
        assertTrue(event.getReceivedAt().isBefore(Instant.now().plusSeconds(1)));
        assertEquals(1, event.getVariableBindings().size());
    }

    @Test
    void testTrapEventWithMultipleVariableBindings() {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0"), new OctetString("value1")));
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.2.0"), new OctetString("value2")));
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.3.0"), new OctetString("value3")));

        TrapEvent event = new TrapEvent(sourceAddress, 1, "private", pdu);

        assertEquals(3, event.getVariableBindings().size());
        assertEquals("value1", event.getVariableBindings().get(0).getVariable().toString());
        assertEquals("value2", event.getVariableBindings().get(1).getVariable().toString());
        assertEquals("value3", event.getVariableBindings().get(2).getVariable().toString());
    }

    @Test
    void testTrapEventWithNullPdu() {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");

        TrapEvent event = new TrapEvent(sourceAddress, 2, "public", null);

        assertNotNull(event);
        assertEquals(0, event.getVariableBindings().size());
    }

    @Test
    void testGetVariableBindingsReturnsCopy() {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0"), new OctetString("test")));

        TrapEvent event = new TrapEvent(sourceAddress, 2, "public", pdu);

        var bindings1 = event.getVariableBindings();
        var bindings2 = event.getVariableBindings();

        assertNotSame(bindings1, bindings2, "Should return a new list each time");
        assertEquals(bindings1.size(), bindings2.size());
    }

    @Test
    void testToString() {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0"), new OctetString("test")));

        TrapEvent event = new TrapEvent(sourceAddress, 2, "public", pdu);

        String toString = event.toString();
        assertTrue(toString.contains("TrapEvent"));
        assertTrue(toString.contains("192.168.1.100"));
        assertTrue(toString.contains("snmpVersion=2"));
        assertTrue(toString.contains("community='public'"));
    }

    @Test
    void testReceivedAtTimestamp() throws InterruptedException {
        UdpAddress sourceAddress = new UdpAddress("192.168.1.100/161");
        PDU pdu = new PDU();

        Instant beforeCreation = Instant.now();
        Thread.sleep(10); // Small delay to ensure different timestamps
        TrapEvent event = new TrapEvent(sourceAddress, 2, "public", pdu);
        Thread.sleep(10);
        Instant afterCreation = Instant.now();

        assertTrue(event.getReceivedAt().isAfter(beforeCreation));
        assertTrue(event.getReceivedAt().isBefore(afterCreation));
    }
}
