
package com.devsecops.securecicdplatform;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class SnykAiAnalysisService {

    private final SnykReportService snykReportService;
    private final AiSecurityAnalysisService aiSecurityAnalysisService;

    public SnykAiAnalysisService(
            SnykReportService snykReportService,
            AiSecurityAnalysisService aiSecurityAnalysisService) {

        this.snykReportService = snykReportService;
        this.aiSecurityAnalysisService = aiSecurityAnalysisService;
    }

    /**
     * Analyse uniquement la première vulnérabilité.
     */
    public String analyzeFirstVulnerability(Path reportPath)
            throws IOException {

        List<String> vulnerabilities =
                snykReportService.extractVulnerabilities(reportPath);

        if (vulnerabilities.isEmpty()) {
            return "Aucune vulnérabilité trouvée dans le rapport Snyk.";
        }

        return aiSecurityAnalysisService.analyzeVulnerability(
                vulnerabilities.get(0)
        );
    }

    /**
     * Analyse toutes les vulnérabilités avec l'IA.
     */
    public String analyzeAllVulnerabilities(Path reportPath)
            throws IOException {

        List<String> vulnerabilities =
                snykReportService.extractVulnerabilities(reportPath);

        if (vulnerabilities.isEmpty()) {
            return "Aucune vulnérabilité trouvée dans le rapport Snyk.";
        }

        StringBuilder report = new StringBuilder();

        report.append("========================================\n");
        report.append("       RAPPORT D'ANALYSE IA SNYK\n");
        report.append("========================================\n");
        report.append("Nombre de vulnérabilités : ")
                .append(vulnerabilities.size())
                .append("\n\n");

        int successfulAnalyses = 0;
        int failedAnalyses = 0;

        for (int i = 0; i < vulnerabilities.size(); i++) {

            report.append("----------------------------------------\n");
            report.append("VULNÉRABILITÉ ")
                    .append(i + 1)
                    .append("/")
                    .append(vulnerabilities.size())
                    .append("\n");
            report.append("----------------------------------------\n");

            try {
                String analysis =
                        aiSecurityAnalysisService.analyzeVulnerability(
                                vulnerabilities.get(i)
                        );

                if (analysis == null || analysis.isBlank()) {
                    failedAnalyses++;

                    report.append(
                            "Échec : l'IA a retourné une analyse vide.\n"
                    );
                } else {
                    report.append(analysis).append("\n");
                    successfulAnalyses++;
                }

            } catch (Exception e) {
                failedAnalyses++;

                System.err.println(
                        "Échec de la vulnérabilité " + (i + 1)
                                + " : " + e.getClass().getSimpleName()
                                + " - " + e.getMessage()
                );

                report.append(
                        "Échec de l'analyse IA. Consulte les logs pour le détail.\n"
                );
            }

            report.append("\n");

            // Pause de 10 secondes entre deux appels à Groq.
            if (i < vulnerabilities.size() - 1) {
                try {
                    TimeUnit.SECONDS.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();

                    throw new IOException(
                            "L'analyse a été interrompue pendant la pause.",
                            e
                    );
                }
            }
        }

        report.append("========================================\n");
        report.append("             RÉSUMÉ FINAL\n");
        report.append("========================================\n");
        report.append("Total : ")
                .append(vulnerabilities.size())
                .append("\n");
        report.append("Analyses réussies : ")
                .append(successfulAnalyses)
                .append("\n");
        report.append("Analyses échouées : ")
                .append(failedAnalyses)
                .append("\n");

        return report.toString();
    }
}
