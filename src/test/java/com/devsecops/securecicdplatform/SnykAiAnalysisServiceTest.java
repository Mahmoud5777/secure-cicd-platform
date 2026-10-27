
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;

@SpringBootTest
class SnykAiAnalysisServiceTest {

    @Autowired
    private SnykAiAnalysisService snykAiAnalysisService;

    @Test
    void shouldAnalyzeAllSnykVulnerabilitiesWithAI() throws Exception {

        Path reportPath = Path.of("src/test/resources/snyk-report-test.json");

        String analysis = snykAiAnalysisService.analyzeFirstVulnerability(reportPath);

        assertNotNull(analysis);
        assertFalse(analysis.isBlank());

        System.out.println("\n");
        System.out.println(analysis);
    }
}
