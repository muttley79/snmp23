package com.arnonse.snmp23.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class EngineStateManager {
    private static final Logger logger = LoggerFactory.getLogger(EngineStateManager.class);
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final File stateFile;

    public EngineStateManager(String filePath) {
        this.stateFile = new File(filePath);
    }

    public synchronized int incrementAndGetBoots(String engineId) {
        Map<String, Integer> engineBoots = new HashMap<>();
        if (stateFile.exists()) {
            try {
                engineBoots = mapper.readValue(stateFile, new TypeReference<Map<String, Integer>>() {});
            } catch (IOException e) {
                logger.error("Failed to read engine state JSON, starting from 0", e);
            }
        }

        int currentBoots = engineBoots.getOrDefault(engineId, 0) + 1;
        engineBoots.put(engineId, currentBoots);

        try {
            mapper.writeValue(stateFile, engineBoots);
        } catch (IOException e) {
            logger.error("Failed to save engine state JSON", e);
        }
        return currentBoots;
    }
}