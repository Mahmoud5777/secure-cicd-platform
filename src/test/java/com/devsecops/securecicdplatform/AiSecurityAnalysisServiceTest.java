
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Assumptions;

class AiSecurityAnalysisServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldRejectEmptyVulnerabilitySummary() {
        AiSecurityAnalysisService service =
                new AiSecurityAnalysisService(
                        objectMapper,
                        "https://api.groq.com/openai/v1",
                        "openai/gpt-oss-20b",
                        "test-api-key"
                );

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyzeVulnerability("")
        );
    }

    @Test
    void shouldRejectNullVulnerabilitySummary() {
        AiSecurityAnalysisService service =
                new AiSecurityAnalysisService(
                        objectMapper,
                        "https://api.groq.com/openai/v1",
                        "openai/gpt-oss-20b",
                        "test-api-key"
                );

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyzeVulnerability(null)
        );
    }

    @Test
    void shouldAnalyzeVulnerabilityWithGroq() {
        String apiKey = System.getenv("GROQ_API_KEY");

        Assumptions.assumeTrue(
                apiKey != null && !apiKey.isBlank(),
                "GROQ_API_KEY absente : test Groq ignoré."
        );

        AiSecurityAnalysisService service =
                new AiSecurityAnalysisService(
                        objectMapper,
                        "https://api.groq.com/openai/v1",
                        "openai/gpt-oss-20b",
                        apiKey
                );

        String result = service.analyzeVulnerability(
                "Vulnérabilité de test : package example-library, "
                        + "version 1.0.0, sévérité LOW. "
                        + "Aucun CVE ni score CVSS renseigné."
        );

        assertNotNull(result);
        assertFalse(result.isBlank());

        System.out.println("Analyse Groq reçue :");
        System.out.println(result);
    }
}
