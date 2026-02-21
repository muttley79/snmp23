package com.arnonse.snmp23.config;

/**
 * Configuration for SNMP trap listener.
 */
public record ListenerConfig(
        String bindAddress,
        int listenPort
) {
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String bindAddress = "0.0.0.0";
        private int listenPort = 9162;

        public Builder bindAddress(String bindAddress) {
            this.bindAddress = bindAddress;
            return this;
        }

        public Builder listenPort(int listenPort) {
            this.listenPort = listenPort;
            return this;
        }

        public ListenerConfig build() {
            return new ListenerConfig(bindAddress, listenPort);
        }
    }
}
