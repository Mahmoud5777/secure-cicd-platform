
package com.devsecops.securecicdplatform;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@RestController
public class SecurityController {

    private final SnykAiAnalysisService snykAiAnalysisService;
    private final SnykStatisticsService snykStatisticsService;

    public SecurityController(
            SnykAiAnalysisService snykAiAnalysisService,
            SnykStatisticsService snykStatisticsService) {

        this.snykAiAnalysisService = snykAiAnalysisService;
        this.snykStatisticsService = snykStatisticsService;
    }

    @GetMapping("/api/status")
    public Map<String, String> getStatus() {
        return Map.of(
                "application", "secure-cicd-platform",
                "status", "UP",
                "security", "DevSecOps"
        );
    }

    @PostMapping("/api/security/statistics")
    public ResponseEntity<?> getStatistics(
            @RequestParam("file") MultipartFile file) throws IOException {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body("Le rapport Snyk est vide.");
        }

        Path tempFile = Files.createTempFile("snyk-report-", ".json");

        try {
            file.transferTo(tempFile.toFile());

            return ResponseEntity.ok(
                    snykStatisticsService.getStatistics(tempFile)
            );

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @GetMapping("/api/security/statistics")
    public ResponseEntity<?> getStatisticsFromReport() throws IOException {

        Path reportPath = Path.of(
                System.getProperty("user.dir"),
                "snyk-report.json"
        );

        if (!Files.exists(reportPath)) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(
                snykStatisticsService.getStatistics(reportPath)
        );
    }

    @PostMapping("/api/security/analyze")
    public ResponseEntity<String> analyzeSnykReport(
            @RequestParam("file") MultipartFile file) throws IOException {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body("Le rapport Snyk est vide.");
        }

        Path tempFile = Files.createTempFile("snyk-report-", ".json");

        try {
            file.transferTo(tempFile.toFile());

            String analysis =
                    snykAiAnalysisService.analyzeAllVulnerabilities(tempFile);

            return ResponseEntity.ok(analysis);

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }


    @PostMapping("/api/security/analyze-latest")
    public ResponseEntity<String> analyzeLatestReport() throws IOException {

        Path reportPath = Path.of(
                "C:\\Users\\ayedi\\Desktop\\secure-cicd-platform\\snyk-report.json"
        );

        if (!Files.exists(reportPath)) {
            return ResponseEntity.notFound()
                    .build();
        }

        String analysis =
                snykAiAnalysisService.analyzeAllVulnerabilities(reportPath);

        return ResponseEntity.ok(analysis);
    }

}
