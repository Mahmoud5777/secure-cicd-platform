
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Assumptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityController.class)
class SecurityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SnykAiAnalysisService snykAiAnalysisService;

    @MockitoBean
    private SnykStatisticsService snykStatisticsService;

    @TempDir
    Path tempDir;

    private String originalUserDir;

    @BeforeEach
    void setUp() {
        originalUserDir = System.getProperty("user.dir");
        System.setProperty("user.dir", tempDir.toString());
    }

    @AfterEach
    void tearDown() {
        if (originalUserDir != null) {
            System.setProperty("user.dir", originalUserDir);
        }
    }

    private MockMultipartFile validReport() {
        return new MockMultipartFile(
                "file",
                "snyk-report.json",
                MediaType.APPLICATION_JSON_VALUE,
                "{\"vulnerabilities\":[]}".getBytes()
        );
    }

    @Test
    void shouldReturnApplicationStatus() throws Exception {
        mockMvc.perform(get("/api/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.application")
                        .value("secure-cicd-platform"))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.security").value("DevSecOps"));
    }

    @Test
    void shouldRejectEmptyStatisticsFile() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "snyk-report.json",
                MediaType.APPLICATION_JSON_VALUE,
                new byte[0]
        );

        mockMvc.perform(multipart("/api/security/statistics").file(file))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Le rapport Snyk est vide."));

        verify(snykStatisticsService, never())
                .getStatistics(any(Path.class));
    }

    @Test
    void shouldProcessStatisticsFile() throws Exception {
        when(snykStatisticsService.getStatistics(any(Path.class)))
                .thenReturn(Map.of("total", 0));

        mockMvc.perform(multipart("/api/security/statistics")
                        .file(validReport()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));

        verify(snykStatisticsService).getStatistics(any(Path.class));
    }

    @Test
    void shouldReturnNotFoundWhenStatisticsReportDoesNotExist()
            throws Exception {

        mockMvc.perform(get("/api/security/statistics"))
                .andExpect(status().isNotFound());

        verify(snykStatisticsService, never())
                .getStatistics(any(Path.class));
    }

    @Test
    void shouldReturnStatisticsWhenReportExists() throws Exception {
        Files.writeString(
                tempDir.resolve("snyk-report.json"),
                "{\"vulnerabilities\":[]}"
        );

        when(snykStatisticsService.getStatistics(any(Path.class)))
                .thenReturn(Map.of("total", 0));

        mockMvc.perform(get("/api/security/statistics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(0));

        verify(snykStatisticsService).getStatistics(any(Path.class));
    }

    @Test
    void shouldRejectEmptyAnalysisFile() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "snyk-report.json",
                MediaType.APPLICATION_JSON_VALUE,
                new byte[0]
        );

        mockMvc.perform(multipart("/api/security/analyze").file(file))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Le rapport Snyk est vide."));

        verify(snykAiAnalysisService, never())
                .analyzeAllVulnerabilities(any(Path.class));
    }

    @Test
    void shouldAnalyzeSnykReport() throws Exception {
        when(snykAiAnalysisService.analyzeAllVulnerabilities(any(Path.class)))
                .thenReturn("Analyse de sécurité terminée.");

        mockMvc.perform(multipart("/api/security/analyze")
                        .file(validReport()))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        "Analyse de sécurité terminée."
                ));

        verify(snykAiAnalysisService)
                .analyzeAllVulnerabilities(any(Path.class));
    }

    @Test
    void shouldReturnNotFoundWhenLatestReportDoesNotExist()
            throws Exception {

        mockMvc.perform(post("/api/security/analyze-latest"))
                .andExpect(status().isNotFound());

        verify(snykAiAnalysisService, never())
                .analyzeAllVulnerabilities(any(Path.class));
    }

    @Test
    void shouldAnalyzeLatestReportWhenItExists() throws Exception {
        Files.writeString(
                tempDir.resolve("snyk-report.json"),
                "{\"vulnerabilities\":[]}"
        );

        when(snykAiAnalysisService.analyzeAllVulnerabilities(any(Path.class)))
                .thenReturn("Analyse terminée.");

        mockMvc.perform(post("/api/security/analyze-latest"))
                .andExpect(status().isOk())
                .andExpect(content().string("Analyse terminée."));

        verify(snykAiAnalysisService)
                .analyzeAllVulnerabilities(any(Path.class));
    }

    @Test
    void shouldRejectSymbolicLinkReportDirectory() throws Exception {
        Path targetDirectory = Files.createDirectory(
                tempDir.resolve("real-reports")
        );

        Path symbolicDirectory = tempDir.resolve("symbolic-reports");

        try {
            Files.createSymbolicLink(symbolicDirectory, targetDirectory);
        } catch (UnsupportedOperationException | IOException
                 | SecurityException exception) {
            Assumptions.abort(
                    "Symbolic links are not supported: "
                            + exception.getMessage()
            );
        }

        SecurityController controller = new SecurityController(
                mock(SnykAiAnalysisService.class),
                mock(SnykStatisticsService.class)
        );

        IOException exception = assertThrows(
                IOException.class,
                () -> controller.createSecureTempFile(symbolicDirectory)
        );

        assertTrue(exception.getMessage().contains(
                "Répertoire de rapports non sécurisé."
        ));
    }
}
