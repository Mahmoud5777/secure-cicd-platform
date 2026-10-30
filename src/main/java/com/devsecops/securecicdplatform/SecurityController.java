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

    public SecurityController(SnykAiAnalysisService snykAiAnalysisService) {
        this.snykAiAnalysisService = snykAiAnalysisService;
    }

    @GetMapping("/api/status")
    public Map<String, String> getStatus() {
        return Map.of(
                "application", "secure-cicd-platform",
                "status", "UP",
                "security", "DevSecOps"
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
}