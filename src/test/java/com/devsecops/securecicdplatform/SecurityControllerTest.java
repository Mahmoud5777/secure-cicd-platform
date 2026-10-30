package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityController.class)
class SecurityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SnykAiAnalysisService snykAiAnalysisService;

    @Test
    void shouldReturnApplicationStatus() throws Exception {
        mockMvc.perform(get("/api/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.application")
                        .value("secure-cicd-platform"))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.security").value("DevSecOps"));
    }
}
