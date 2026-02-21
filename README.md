# SNMP Trap Forwarder

A lightweight Java service that receives **SNMPv1/v2c traps** and forwards them as **SNMPv3 traps** with authentication and privacy (authPriv security level).

## Overview

Many legacy devices and applications can only emit SNMPv1 or SNMPv2c traps, which are sent in plaintext with no authentication. This tool acts as a protocol bridge: it listens for those insecure traps and re-transmits them to a target SNMP manager using SNMPv3 with full authentication and encryption.

```
[Legacy Device]                    [SNMP Forwarder]                  [NMS / SNMP Manager]
  SNMPv1 trap   ──────────────►  Listener (UDP)                    SNMPv3 authPriv trap
  SNMPv2c trap  ──────────────►  Port 1162       ──────────────►   Port 162
                                  ↓ forwards as
                                  SNMPv3 (SHA + AES)
```

## Features

- Accepts SNMPv1 and SNMPv2c traps on a configurable UDP port
- Forwards traps as SNMPv3 with `authPriv` security level
- Supports multiple authentication protocols: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- Supports multiple privacy protocols: DES, AES-128, AES-192, AES-256
- Persists SNMPv3 engine boot count across restarts (required for RFC 3414 compliance)
- Multi-threaded trap listener (4-thread pool)
- Rolling file logging (30-day retention) with console output
- Graceful shutdown via JVM shutdown hook
- Externalized configuration via properties file

## Requirements

- Java 21+
- Maven 3.6+ (for building)

## Building

```bash
mvn clean package
```

This produces a fat JAR (via maven-shade-plugin) at:

```
target/snmp-forwarder-1.0.0.jar
```

## Configuration

All settings are in `application.properties`. A custom path can be passed as the first command-line argument.

```properties
# Listener – where to receive incoming SNMPv1/v2c traps
listener.bindAddress=0.0.0.0
listener.port=1162

# SNMPv3 sender – where to forward traps
v3.targetHost=192.168.1.100
v3.targetPort=162
v3.username=myUser
v3.authPassword=MyAuthPass123!
v3.privPassword=MyPrivPass123!
v3.engineId=0x8000047304434b4d39383736353433323130
v3.authProtocol=SHA          # MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
v3.privProtocol=AES          # DES | AES | AES128 | AES192 | AES256

# Engine state persistence (tracks boot count for SNMPv3 replay protection)
state.file=engine-state.json
```

### Configuration Reference

| Property | Default | Description |
|---|---|---|
| `listener.bindAddress` | `0.0.0.0` | IP address to bind the listener to |
| `listener.port` | `1162` | UDP port to listen for incoming traps |
| `v3.targetHost` | *(required)* | Hostname or IP of the SNMPv3 target |
| `v3.targetPort` | `162` | UDP port of the SNMPv3 target |
| `v3.username` | *(required)* | SNMPv3 USM username |
| `v3.authPassword` | *(required)* | Authentication password (min 8 chars) |
| `v3.privPassword` | *(required)* | Privacy/encryption password (min 8 chars) |
| `v3.engineId` | *(required)* | Hex-encoded SNMPv3 engine ID (e.g. `0x8000...`) |
| `v3.authProtocol` | `SHA` | Authentication protocol |
| `v3.privProtocol` | `AES` | Privacy (encryption) protocol |
| `state.file` | `engine-state.json` | Path to engine boot-count state file |

### Engine ID

The engine ID must match what is configured on the target SNMP manager. It is a hex string prefixed with `0x`. The forwarder parses it and uses it as the authoritative engine ID when sending SNMPv3 traps.

The engine boot count is incremented on each start and stored in the state file (`engine-state.json`). This count is essential for SNMPv3 replay attack prevention as defined in RFC 3414.

## Running

```bash
# Using the default application.properties in the current directory
java -jar target/snmp-forwarder-1.0.0.jar

# Using a custom config file path
java -jar target/snmp-forwarder-1.0.0.jar /etc/snmp-forwarder/production.properties
```

> **Note:** Port 1162 is used by default to avoid requiring root privileges. If you need to listen on the standard trap port (162), either run as root or configure OS-level port redirection (e.g., `iptables` on Linux).

## Project Structure

```
src/
└── main/
    ├── java/com/arnonse/snmp23/
    │   ├── SnmpForwarderApplication.java   # Entry point, wires listener and sender
    │   ├── config/
    │   │   ├── ListenerConfig.java         # Listener bind address and port
    │   │   └── SnmpV3Config.java           # SNMPv3 target and security settings
    │   ├── listener/
    │   │   └── SnmpTrapListener.java       # Receives SNMPv1/v2c traps (multi-threaded)
    │   ├── model/
    │   │   └── TrapEvent.java              # Immutable representation of a received trap
    │   ├── sender/
    │   │   └── SnmpV3TrapSender.java       # Forwards traps as SNMPv3 authPriv
    │   └── service/
    │       └── EngineStateManager.java     # Persists engine boot count to JSON
    └── resources/
        ├── application.properties          # Default configuration
        ├── logback.xml                     # Logging configuration
        ├── sendv2                          # Test script: send SNMPv2c trap
        ├── sendv3                          # Test script: send SNMPv3 trap directly
        └── trapd                           # Snippet: run snmptrapd for debugging
```

## Logging

Logs are written to both the console and a rolling log file:

- **Console:** standard output, INFO level and above
- **File:** `logs/snmp-forwarder.log`, rotated daily, 30 days retention
- **Application package** (`com.arnonse.snmp23`): DEBUG level
- **SNMP4J library:** INFO level

The log pattern is:
```
2026-02-21 14:30:00.000 [main] INFO  c.a.s.SnmpForwarderApplication - Starting SNMP Trap Forwarder
```

## Testing

### Unit / Integration Tests

```bash
mvn test
```

The `EndToEndForwardingTest` starts a local listener on port `11162`, sends a synthetic SNMPv2c trap, and verifies that the forwarder processes and forwards it.

### Manual Testing with net-snmp

**Send a test SNMPv2c trap** to the forwarder:

```bash
snmptrap \
  -v2c -c public \
  <forwarder-host>:1162 \
  "" \
  .1.3.6.1.2.1.1.0 \
  .1.3.6.1.2.1.1.1.0 s "Test trap payload"
```

**Receive SNMPv3 traps** on the target side with `snmptrapd`:

```bash
sudo snmptrapd -f -Lo -n -d
```

The helper scripts in `src/main/resources/` provide ready-to-use examples for the test environment.

## Dependencies

| Library | Version | Purpose |
|---|---|---|
| [SNMP4J](https://www.snmp4j.org/) | 3.8.2 | SNMP protocol implementation |
| [SLF4J](https://www.slf4j.org/) | 2.0.12 | Logging facade |
| [Logback](https://logback.qos.ch/) | 1.5.x | Logging implementation |
| [Jackson Databind](https://github.com/FasterXML/jackson) | 2.15.2 | JSON engine state persistence |
| JUnit Jupiter | 5.10.1 | Unit testing |
| Mockito | 5.8.0 | Mocking in tests |

## Security Notes

- The `application.properties` file contains credentials (`authPassword`, `privPassword`). Restrict file permissions appropriately and do not commit credentials to source control.
- The `engine-state.json` file must be writable by the process and preserved across restarts. Loss of this file will reset the boot counter to 1, which may cause the target SNMP manager to reject traps until the counter exceeds its cached value.
- SNMPv3 `authPriv` security level is enforced for all outbound traps (authentication + encryption). Inbound traps are accepted without authentication, as SNMPv1/v2c have no authentication mechanism.
