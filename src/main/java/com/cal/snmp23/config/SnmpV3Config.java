package com.cal.snmp23.config;

/**
 * Configuration for SNMPv3 sender.
 */
public record SnmpV3Config(
        String targetHost,
        int targetPort,
        String username,
        String authPassword,
        String privPassword,
        String engineId,
        AuthProtocol authProtocol,
        PrivProtocol privProtocol
) {
    public enum AuthProtocol {
        MD5, SHA, SHA224, SHA256, SHA384, SHA512
    }

    public enum PrivProtocol {
        DES, AES, AES128, AES192, AES256
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String targetHost;
        private int targetPort = 162;
        private String username;
        private String authPassword;
        private String privPassword;
        private String engineId;
        private AuthProtocol authProtocol = AuthProtocol.SHA;
        private PrivProtocol privProtocol = PrivProtocol.AES;

        public Builder targetHost(String targetHost) {
            this.targetHost = targetHost;
            return this;
        }

        public Builder targetPort(int targetPort) {
            this.targetPort = targetPort;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder authPassword(String authPassword) {
            this.authPassword = authPassword;
            return this;
        }

        public Builder privPassword(String privPassword) {
            this.privPassword = privPassword;
            return this;
        }

        public Builder engineId(String engineId) {
            this.engineId = engineId;
            return this;
        }

        public Builder authProtocol(AuthProtocol authProtocol) {
            this.authProtocol = authProtocol;
            return this;
        }

        public Builder privProtocol(PrivProtocol privProtocol) {
            this.privProtocol = privProtocol;
            return this;
        }

        public SnmpV3Config build() {
            if (targetHost == null || targetHost.isEmpty()) {
                throw new IllegalArgumentException("Target host is required");
            }
            if (username == null || username.isEmpty()) {
                throw new IllegalArgumentException("Username is required");
            }
            if (authPassword == null || authPassword.isEmpty()) {
                throw new IllegalArgumentException("Auth password is required");
            }
            if (privPassword == null || privPassword.isEmpty()) {
                throw new IllegalArgumentException("Priv password is required");
            }
            if (engineId == null || engineId.isEmpty()) {
                throw new IllegalArgumentException("Engine ID is required");
            }
            return new SnmpV3Config(
                    targetHost,
                    targetPort,
                    username,
                    authPassword,
                    privPassword,
                    engineId,
                    authProtocol,
                    privProtocol
            );
        }
    }
}
