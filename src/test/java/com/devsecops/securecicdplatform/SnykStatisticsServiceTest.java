
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import tools.jackson.core.exc.StreamReadException;

class SnykStatisticsServiceTest {

    @TempDir
    Path tempDir;

    private final SnykStatisticsService service =
            new SnykStatisticsService(JsonMapper.builder().build());

    @Test
    void shouldCountAllVulnerabilitySeverities() throws IOException {

        Path report = tempDir.resolve("snyk-report.json");

        Files.writeString(report, """
                {
                  "vulnerabilities": [
                    {"severity": "critical"},
                    {"severity": "high"},
                    {"severity": "high"},
                    {"severity": "medium"},
                    {"severity": "low"},
                    {"severity": "low"},
                    {"severity": "low"}
                  ]
                }
                """);

        Map<String, Integer> result = service.getStatistics(report);

        assertEquals(7, result.get("total"));
        assertEquals(1, result.get("critical"));
        assertEquals(2, result.get("high"));
        assertEquals(1, result.get("medium"));
        assertEquals(3, result.get("low"));
    }

    @Test
    void shouldHandleUppercaseSeverities() throws IOException {

        Path report = tempDir.resolve("uppercase-report.json");

        Files.writeString(report, """
                {
                  "vulnerabilities": [
                    {"severity": "CRITICAL"},
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                    {"severity": "LOW"}
                  ]
                }
                """);

        Map<String, Integer> result = service.getStatistics(report);

        assertEquals(4, result.get("total"));
        assertEquals(1, result.get("critical"));
        assertEquals(1, result.get("high"));
        assertEquals(1, result.get("medium"));
        assertEquals(1, result.get("low"));
    }

    @Test
    void shouldIgnoreUnknownOrMissingSeverities() throws IOException {

        Path report = tempDir.resolve("unknown-report.json");

        Files.writeString(report, """
                {
                  "vulnerabilities": [
                    {"severity": "unknown"},
                    {},
                    {"severity": "negligible"}
                  ]
                }
                """);

        Map<String, Integer> result = service.getStatistics(report);

        assertEquals(0, result.get("total"));
        assertEquals(0, result.get("critical"));
        assertEquals(0, result.get("high"));
        assertEquals(0, result.get("medium"));
        assertEquals(0, result.get("low"));
    }

    @Test
    void shouldRejectReportWithoutVulnerabilitiesArray() throws IOException {

        Path report = tempDir.resolve("invalid-report.json");

        Files.writeString(report, """
                {
                  "project": "secure-cicd-platform"
                }
                """);

        IOException exception = assertThrows(
                IOException.class,
                () -> service.getStatistics(report)
        );

        assertEquals("Rapport Snyk invalide.", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidJson() throws IOException {

        Path report = tempDir.resolve("malformed-report.json");

        Files.writeString(report, "{ invalid json }");

        assertThrows(
                StreamReadException.class,
                () -> service.getStatistics(report)
        );
    }
}
