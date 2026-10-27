
package com.devsecops.securecicdplatform;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

@SpringBootTest
class SnykReportServiceTest {

    @Autowired
    private SnykReportService snykReportService;

    @Test
    void shouldExtractVulnerabilitiesFromSnykReport()
            throws Exception {

        Path reportPath = Path.of("snyk-report.json");

        List<String> vulnerabilities =
                snykReportService.extractVulnerabilities(reportPath);

        assertFalse(
                vulnerabilities.isEmpty(),
                "Le rapport devrait contenir des vulnérabilités"
        );

        System.out.println(
                "Nombre de vulnérabilités extraites : "
                        + vulnerabilities.size()
        );

        System.out.println(vulnerabilities.get(0));
    }
}
