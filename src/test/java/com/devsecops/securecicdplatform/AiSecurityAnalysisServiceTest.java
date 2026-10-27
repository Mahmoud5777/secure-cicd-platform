
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertThrows;

class AiSecurityAnalysisServiceTest {

    @Test
    void shouldRejectEmptyVulnerabilitySummary() {
        AiSecurityAnalysisService service =
                new AiSecurityAnalysisService(new ObjectMapper());

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyzeVulnerability("")
        );
    }

    @Test
    void shouldRejectNullVulnerabilitySummary() {
        AiSecurityAnalysisService service =
                new AiSecurityAnalysisService(new ObjectMapper());

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyzeVulnerability(null)
        );
    }
}
