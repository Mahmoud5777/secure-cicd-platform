package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class SnykAiAnalysisServiceTest {

    @Autowired
    private SnykAiAnalysisService snykAiAnalysisService;

    @MockitoBean
    private AiSecurityAnalysisService aiSecurityAnalysisService;

    @MockitoBean
    private SnykReportService snykReportService;

    private final Path reportPath = Path.of("snyk-report-test.json");

    @Test
    void shouldAnalyzeFirstVulnerability() throws Exception {

        when(snykReportService.extractVulnerabilities(reportPath))
                .thenReturn(java.util.List.of("Vulnérabilité A", "Vulnérabilité B"));

        when(aiSecurityAnalysisService.analyzeVulnerability("Vulnérabilité A"))
                .thenReturn("Analyse IA réussie.");

        String result =
                snykAiAnalysisService.analyzeFirstVulnerability(reportPath);

        assertEquals("Analyse IA réussie.", result);

        verify(aiSecurityAnalysisService, times(1))
                .analyzeVulnerability("Vulnérabilité A");
    }

    @Test
    void shouldReturnMessageWhenNoVulnerabilitiesExist() throws Exception {

        when(snykReportService.extractVulnerabilities(reportPath))
                .thenReturn(java.util.List.of());

        String result =
                snykAiAnalysisService.analyzeAllVulnerabilities(reportPath);

        assertTrue(result.contains("Aucune vulnérabilité"));

        verifyNoInteractions(aiSecurityAnalysisService);
    }

    @Test
    void shouldAnalyzeAllVulnerabilities() throws Exception {

        when(snykReportService.extractVulnerabilities(reportPath))
                .thenReturn(java.util.List.of("Vulnérabilité A"));

        when(aiSecurityAnalysisService.analyzeVulnerability("Vulnérabilité A"))
                .thenReturn("Analyse IA réussie.");

        String result =
                snykAiAnalysisService.analyzeAllVulnerabilities(reportPath);

        assertTrue(result.contains("Analyses réussies : 1"));
        assertTrue(result.contains("Analyses échouées : 0"));
        assertTrue(result.contains("Analyse IA réussie."));

        verify(aiSecurityAnalysisService, times(1))
                .analyzeVulnerability("Vulnérabilité A");
    }

    @Test
    void shouldHandleEmptyAiResponse() throws Exception {

        when(snykReportService.extractVulnerabilities(reportPath))
                .thenReturn(java.util.List.of("Vulnérabilité A"));

        when(aiSecurityAnalysisService.analyzeVulnerability(anyString()))
                .thenReturn(" ");

        String result =
                snykAiAnalysisService.analyzeAllVulnerabilities(reportPath);

        assertTrue(result.contains("Analyses réussies : 0"));
        assertTrue(result.contains("Analyses échouées : 1"));
    }

    @Test
    void shouldHandleAiException() throws Exception {

        when(snykReportService.extractVulnerabilities(reportPath))
                .thenReturn(java.util.List.of("Vulnérabilité A"));

        when(aiSecurityAnalysisService.analyzeVulnerability(anyString()))
                .thenThrow(new RuntimeException("Erreur IA simulée"));

        String result =
                snykAiAnalysisService.analyzeAllVulnerabilities(reportPath);

        assertTrue(result.contains("Analyses échouées : 1"));
        assertTrue(result.contains("Échec de l'analyse IA"));
    }
}