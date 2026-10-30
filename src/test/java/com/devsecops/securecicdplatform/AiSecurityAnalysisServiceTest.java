
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
