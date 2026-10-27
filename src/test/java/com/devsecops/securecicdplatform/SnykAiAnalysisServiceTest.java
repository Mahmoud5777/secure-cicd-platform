
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

@SpringBootTest
class SnykAiAnalysisServiceTest {

    @Autowired
    private SnykAiAnalysisService snykAiAnalysisService;

    @MockitoBean
    private AiSecurityAnalysisService aiSecurityAnalysisService;

    @Test
    void shouldAnalyzeAllSnykVulnerabilitiesWithAI() throws Exception {

        when(aiSecurityAnalysisService.analyzeVulnerability(anyString()))
                .thenReturn("Analyse IA simulée pour le test.");

        Path reportPath =
                Path.of("src/test/resources/snyk-report-test.json");

        String analysis =
                snykAiAnalysisService.analyzeFirstVulnerability(reportPath);

        assertNotNull(analysis);
        assertFalse(analysis.isBlank());
        assertFalse(analysis.contains("Échec"));

        verify(aiSecurityAnalysisService, times(1))
                .analyzeVulnerability(anyString());
    }
}
