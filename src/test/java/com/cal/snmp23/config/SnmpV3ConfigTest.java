package com.cal.snmp23.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SnmpV3ConfigTest {

    @Test
    void testBuilderWithAllFields() {
        SnmpV3Config config = SnmpV3Config.builder()
                .targetHost("192.168.1.1")
                .targetPort(162)
                .username("testUser")
                .authPassword("authPass123")
                .privPassword("privPass123")
                .engineId("0x8000047304434b4d39383736353433323130")
                .authProtocol(SnmpV3Config.AuthProtocol.SHA)
                .privProtocol(SnmpV3Config.PrivProtocol.AES)
                .build();

        assertEquals("192.168.1.1", config.targetHost());
        assertEquals(162, config.targetPort());
        assertEquals("testUser", config.username());
        assertEquals("authPass123", config.authPassword());
        assertEquals("privPass123", config.privPassword());
        assertEquals("0x8000047304434b4d39383736353433323130", config.engineId());
        assertEquals(SnmpV3Config.AuthProtocol.SHA, config.authProtocol());
        assertEquals(SnmpV3Config.PrivProtocol.AES, config.privProtocol());
    }

    @Test
    void testBuilderWithDefaults() {
        SnmpV3Config config = SnmpV3Config.builder()
                .targetHost("192.168.1.1")
                .username("testUser")
                .authPassword("authPass123")
                .privPassword("privPass123")
                .engineId("0x123456")
                .build();

        assertEquals(162, config.targetPort());
        assertEquals(SnmpV3Config.AuthProtocol.SHA, config.authProtocol());
        assertEquals(SnmpV3Config.PrivProtocol.AES, config.privProtocol());
    }

    @Test
    void testBuilderMissingTargetHost() {
        assertThrows(IllegalArgumentException.class, () ->
                SnmpV3Config.builder()
                        .username("testUser")
                        .authPassword("authPass123")
                        .privPassword("privPass123")
                        .engineId("0x123456")
                        .build()
        );
    }

    @Test
    void testBuilderMissingUsername() {
        assertThrows(IllegalArgumentException.class, () ->
                SnmpV3Config.builder()
                        .targetHost("192.168.1.1")
                        .authPassword("authPass123")
                        .privPassword("privPass123")
                        .engineId("0x123456")
                        .build()
        );
    }

    @Test
    void testBuilderMissingAuthPassword() {
        assertThrows(IllegalArgumentException.class, () ->
                SnmpV3Config.builder()
                        .targetHost("192.168.1.1")
                        .username("testUser")
                        .privPassword("privPass123")
                        .engineId("0x123456")
                        .build()
        );
    }

    @Test
    void testBuilderMissingPrivPassword() {
        assertThrows(IllegalArgumentException.class, () ->
                SnmpV3Config.builder()
                        .targetHost("192.168.1.1")
                        .username("testUser")
                        .authPassword("authPass123")
                        .engineId("0x123456")
                        .build()
        );
    }

    @Test
    void testBuilderMissingEngineId() {
        assertThrows(IllegalArgumentException.class, () ->
                SnmpV3Config.builder()
                        .targetHost("192.168.1.1")
                        .username("testUser")
                        .authPassword("authPass123")
                        .privPassword("privPass123")
                        .build()
        );
    }

    @Test
    void testAllAuthProtocols() {
        for (SnmpV3Config.AuthProtocol protocol : SnmpV3Config.AuthProtocol.values()) {
            SnmpV3Config config = SnmpV3Config.builder()
                    .targetHost("192.168.1.1")
                    .username("testUser")
                    .authPassword("authPass123")
                    .privPassword("privPass123")
                    .engineId("0x123456")
                    .authProtocol(protocol)
                    .build();

            assertEquals(protocol, config.authProtocol());
        }
    }

    @Test
    void testAllPrivProtocols() {
        for (SnmpV3Config.PrivProtocol protocol : SnmpV3Config.PrivProtocol.values()) {
            SnmpV3Config config = SnmpV3Config.builder()
                    .targetHost("192.168.1.1")
                    .username("testUser")
                    .authPassword("authPass123")
                    .privPassword("privPass123")
                    .engineId("0x123456")
                    .privProtocol(protocol)
                    .build();

            assertEquals(protocol, config.privProtocol());
        }
    }
}
