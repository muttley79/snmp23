package com.arnonse.snmp23.sender;

import com.arnonse.snmp23.config.SnmpV3Config;
import com.arnonse.snmp23.model.TrapEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class SnmpV3TrapSender {
    private static final Logger logger = LoggerFactory.getLogger(SnmpV3TrapSender.class);

    private final SnmpV3Config config;
    private Snmp snmp;
    private USM usm;
    private final Set<String> registeredUsers = new HashSet<>();
    private final long startTime = System.currentTimeMillis();

    public SnmpV3TrapSender(SnmpV3Config config) {
        this.config = config;
    }

    public void initialize(int engineBoots) throws IOException {
        logger.info("Initializing SNMPv3 trap sender for target {}:{}",
                config.targetHost(), config.targetPort());

        SecurityProtocols protocols = SecurityProtocols.getInstance();
        protocols.addDefaultProtocols();
        // RESTORED: Explicitly adding protocols to ensure SecurityLevel.AUTH_PRIV works
        protocols.addAuthenticationProtocol(new AuthSHA());
        protocols.addAuthenticationProtocol(new AuthMD5());
        protocols.addPrivacyProtocol(new PrivAES128());
        protocols.addPrivacyProtocol(new PrivAES192());
        protocols.addPrivacyProtocol(new PrivAES256());
        protocols.addPrivacyProtocol(new PrivDES());

        TransportMapping<?> transport = new DefaultUdpTransportMapping();
        MessageDispatcher dispatcher = new MessageDispatcherImpl();

        OctetString customEngineId = parseEngineId(config.engineId());

        // Use the persisted boot count from JSON
        usm = new USM(protocols, customEngineId, engineBoots);
        SecurityModels.getInstance().addSecurityModel(usm);

        dispatcher.addMessageProcessingModel(new MPv3(usm));

        snmp = new Snmp(dispatcher, transport);
        transport.listen();

        logger.info("SNMPv3 trap sender initialized with EngineID: {} and Boots: {}",
                customEngineId.toHexString(), engineBoots);
    }

    public void sendTrap(TrapEvent trapEvent) {
        try {
            OctetString targetEngineId = parseEngineId(config.engineId());
            OctetString secName = new OctetString(config.username());

            ensureUserRegistered(secName, targetEngineId);

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            long uptimeCentiseconds = (System.currentTimeMillis() - startTime) / 10;
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(uptimeCentiseconds)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, getTrapOid(trapEvent)));

            for (VariableBinding vb : trapEvent.getVariableBindings()) {
                OID oid = vb.getOid();
                if (!oid.equals(SnmpConstants.sysUpTime) && !oid.equals(SnmpConstants.snmpTrapOID)) {
                    pdu.add(vb);
                }
            }

            UserTarget target = new UserTarget();
            target.setAddress(new UdpAddress(config.targetHost() + "/" + config.targetPort()));
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(secName);
            target.setAuthoritativeEngineID(targetEngineId.getValue());
            target.setTimeout(2000);
            target.setRetries(1);

            snmp.send(pdu, target);
            logger.info("Trap successfully forwarded to {}", config.targetHost());

        } catch (Exception e) {
            logger.error("Trap forwarding failed: " + e.getMessage(), e);
        }
    }

    private synchronized void ensureUserRegistered(OctetString secName, OctetString engineId) {
        String userKey = secName.toString() + ":" + engineId.toHexString();
        if (!registeredUsers.contains(userKey)) {
            UsmUser user = new UsmUser(
                    secName,
                    getAuthProtocolOid(config.authProtocol()),
                    new OctetString(config.authPassword()),
                    getPrivProtocolOid(config.privProtocol()),
                    new OctetString(config.privPassword())
            );

            snmp.getUSM().addUser(secName, user);
            registeredUsers.add(userKey);
        }
    }

    public void close() throws IOException {
        if (snmp != null) snmp.close();
        logger.info("SNMPv3 trap sender closed");
    }

    private OID getTrapOid(TrapEvent trapEvent) {
        for (VariableBinding vb : trapEvent.getVariableBindings()) {
            if (vb.getOid().equals(SnmpConstants.snmpTrapOID)) {
                return (OID) vb.getVariable();
            }
        }
        return new OID("1.3.6.1.2.1.1331.11.1.152.0");
    }

    private OctetString parseEngineId(String engineIdHex) {
        String hex = engineIdHex.toLowerCase().replace("0x", "").replace(":", "");
        if (hex.length() % 2 != 0) hex = "0" + hex;
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return new OctetString(data);
    }

    private OID getAuthProtocolOid(SnmpV3Config.AuthProtocol protocol) {
        return switch (protocol) {
            case MD5 -> AuthMD5.ID;
            case SHA -> AuthSHA.ID;
            case SHA224 -> AuthHMAC128SHA224.ID;
            case SHA256 -> AuthHMAC192SHA256.ID;
            case SHA384 -> AuthHMAC256SHA384.ID;
            case SHA512 -> AuthHMAC384SHA512.ID;
        };
    }

    private OID getPrivProtocolOid(SnmpV3Config.PrivProtocol protocol) {
        return switch (protocol) {
            case DES -> PrivDES.ID;
            case AES, AES128 -> PrivAES128.ID;
            case AES192 -> PrivAES192.ID;
            case AES256 -> PrivAES256.ID;
        };
    }
}