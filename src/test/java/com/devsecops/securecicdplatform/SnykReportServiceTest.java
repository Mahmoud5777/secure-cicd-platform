
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SnykReportServiceTest {

    @Autowired
    private SnykReportService snykReportService;

    @TempDir
    Path tempDir;

    private Path createReport(String json) throws IOException {
        Path report = tempDir.resolve("snyk-report.json");
        Files.writeString(report, json);
        return report;
    }

    @Test
    void shouldExtractVulnerabilitiesFromSnykReport() throws Exception {
        Path reportPath = Path.of("src/test/resources/snyk-report-test.json");

        List<String> vulnerabilities =
                snykReportService.extractVulnerabilities(reportPath);

        assertFalse(vulnerabilities.isEmpty());
    }

    @Test
    void shouldRejectReportWithoutVulnerabilitiesArray() throws Exception {
        Path report = createReport("{\"name\":\"test\"}");

        IOException exception = assertThrows(
                IOException.class,
                () -> snykReportService.extractVulnerabilities(report)
        );

        assertTrue(exception.getMessage().contains("vulnerabilities"));
    }

    @Test
    void shouldIgnoreNonObjectVulnerabilities() throws Exception {
        Path report = createReport("""
                {
                  "vulnerabilities": [
                    "texte",
                    42,
                    null,
                    {
                      "id": "SNYK-TEST",
                      "severity": "high"
                    }
                  ]
                }
                """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("SNYK-TEST"));
    }

    @Test
    void shouldHandleMissingOptionalFields() throws Exception {
        Path report = createReport("""
                {
                  "vulnerabilities": [
                    {
                      "id": "",
                      "title": "Test"
                    }
                  ]
                }
                """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("Non renseigné"));
        assertTrue(result.get(0).contains("Non indiquées"));
    }

    @Test
    void shouldExtractCveFixedVersionsAndDependencyPath() throws Exception {
        Path report = createReport("""
                {
                  "vulnerabilities": [
                    {
                      "id": "SNYK-TEST-123",
                      "title": "Test vulnerability",
                      "severity": "high",
                      "packageName": "example-package",
                      "version": "1.0.0",
                      "description": "Test description",
                      "cvssScore": "8.5",
                      "from": [
                        "root-project",
                        "dependency-a",
                        "",
                        null,
                        "dependency-b"
                      ],
                      "fixedIn": [
                        "1.0.1",
                        "",
                        null,
                        "1.0.2"
                      ],
                      "identifiers": {
                        "CVE": ["CVE-2026-12345"]
                      }
                    }
                  ]
                }
                """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());

        String summary = result.get(0);

        assertTrue(summary.contains("CVE-2026-12345"));
        assertTrue(summary.contains("root-project -> dependency-a -> dependency-b"));
        assertTrue(summary.contains("1.0.1, 1.0.2"));
        assertTrue(summary.contains("8.5"));
    }

    @Test
    void shouldHandleEmptyDependencyPathAndCveList() throws Exception {
        Path report = createReport("""
                {
                  "vulnerabilities": [
                    {
                      "id": "SNYK-EMPTY",
                      "from": [],
                      "identifiers": {
                        "CVE": []
                      },
                      "fixedIn": []
                    }
                  ]
                }
                """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("Non renseigné"));
        assertTrue(result.get(0).contains("Non indiquées"));
    }

    @Test
    void shouldRejectInvalidJson() throws Exception {
        Path report = createReport("{invalid json");

        assertThrows(
                tools.jackson.core.exc.StreamReadException.class,
                () -> snykReportService.extractVulnerabilities(report)
        );
    }


    @Test
    void shouldIgnoreFixedVersionsWhenFixedInIsNotAnArray() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": "SNYK-TEST",
                  "fixedIn": "1.0.1",
                  "identifiers": {
                    "CVE": "CVE-2026-12345"
                  }
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("Non indiquées"));
        assertTrue(result.get(0).contains("Non renseigné"));
    }

    @Test
    void shouldHandleFixedVersionsAndCveWithEmptyText() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": "SNYK-EMPTY",
                  "fixedIn": [""],
                  "identifiers": {
                    "CVE": [""]
                  }
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("Non renseigné"));
        assertTrue(result.get(0).contains("Non indiquées"));
    }


    @Test
    void shouldIgnoreNullFixedVersion() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": "SNYK-NULL-FIX",
                  "fixedIn": [null, "1.0.1"]
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("1.0.1"));
    }


    @Test
    void shouldHandleNullOptionalFields() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": null,
                  "title": null,
                  "severity": null
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains("Identifiant Snyk : Non renseigné"));
        assertTrue(result.get(0).contains("Titre : Non renseigné"));
        assertTrue(result.get(0).contains("Sévérité : Non renseigné"));
    }


    @Test
    void shouldIgnoreNullElementsInDependencyPath() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": "SNYK-PATH-TEST",
                  "from": [
                    null,
                    "root-project",
                    "dependency-a"
                  ]
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains(
                "root-project -> dependency-a"
        ));
    }


    @Test
    void shouldRejectEmptyReport() throws Exception {
        Path report = createReport("");

        assertThrows(
                IOException.class,
                () -> snykReportService.extractVulnerabilities(report)
        );
    }

    @Test
    void shouldHandleDependencyPathWithOnlyEmptyElements() throws Exception {
        Path report = createReport("""
            {
              "vulnerabilities": [
                {
                  "id": "SNYK-EMPTY-PATH",
                  "from": ["", null, "   "]
                }
              ]
            }
            """);

        List<String> result =
                snykReportService.extractVulnerabilities(report);

        assertEquals(1, result.size());
        assertTrue(result.get(0).contains(
                "Chemin de dépendance : Non renseigné"
        ));
    }

    @Test
    void shouldRejectNonObjectJsonRoot() throws Exception {
        Path report = createReport("[]");

        IOException exception = assertThrows(
                IOException.class,
                () -> snykReportService.extractVulnerabilities(report)
        );

        assertTrue(exception.getMessage().contains("invalide"));
    }


}
