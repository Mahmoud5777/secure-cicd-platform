
package com.devsecops.securecicdplatform;

import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;

@Service
public class SnykStatisticsService {

    private final ObjectMapper objectMapper;

    public SnykStatisticsService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Map<String, Integer> getStatistics(Path reportPath)
            throws IOException {

        JsonNode root = objectMapper.readTree(reportPath.toFile());
        JsonNode vulnerabilities = root.path("vulnerabilities");

        if (!vulnerabilities.isArray()) {
            throw new IOException("Rapport Snyk invalide.");
        }

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        for (JsonNode vulnerability : vulnerabilities) {
            String severity = vulnerability
                    .path("severity")
                    .asText("")
                    .toLowerCase(Locale.ROOT);

            switch (severity) {
                case "critical" -> critical++;
                case "high" -> high++;
                case "medium" -> medium++;
                case "low" -> low++;
            }
        }

        return Map.of(
                "total", critical + high + medium + low,
                "critical", critical,
                "high", high,
                "medium", medium,
                "low", low
        );
    }
}
