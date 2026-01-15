package com.cal.snmp23.model;

import org.snmp4j.PDU;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.VariableBinding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an SNMP trap event received by the listener.
 */
public class TrapEvent {
    private final Address sourceAddress;
    private final Instant receivedAt;
    private final int snmpVersion;
    private final String community;
    private final PDU pdu;
    private final List<VariableBinding> variableBindings;

    public TrapEvent(Address sourceAddress, int snmpVersion, String community, PDU pdu) {
        this.sourceAddress = sourceAddress;
        this.receivedAt = Instant.now();
        this.snmpVersion = snmpVersion;
        this.community = community;
        this.pdu = pdu;
        this.variableBindings = new ArrayList<>();
        
        if (pdu != null && pdu.getVariableBindings() != null) {
            this.variableBindings.addAll(pdu.getVariableBindings());
        }
    }

    public Address getSourceAddress() {
        return sourceAddress;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }

    public int getSnmpVersion() {
        return snmpVersion;
    }

    public String getCommunity() {
        return community;
    }

    public PDU getPdu() {
        return pdu;
    }

    public List<VariableBinding> getVariableBindings() {
        return new ArrayList<>(variableBindings);
    }

    @Override
    public String toString() {
        return "TrapEvent{" +
                "sourceAddress=" + sourceAddress +
                ", receivedAt=" + receivedAt +
                ", snmpVersion=" + snmpVersion +
                ", community='" + community + '\'' +
                ", variableBindings=" + variableBindings.size() +
                '}';
    }
}
