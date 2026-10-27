
package com.devsecops.securecicdplatform;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
public class SnykReportService {

    private final ObjectMapper objectMapper;

    public SnykReportService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<String> extractVulnerabilities(Path reportPath)
            throws IOException {

        JsonNode root = objectMapper.readTree(reportPath.toFile());

        if (root == null || !root.isObject()) {
            throw new IOException(
                    "Le rapport Snyk est vide ou invalide."
            );
        }

        JsonNode vulnerabilities = root.path("vulnerabilities");

        if (!vulnerabilities.isArray()) {
            throw new IOException(
                    "Le champ 'vulnerabilities' est absent "
                            + "ou n'est pas un tableau."
            );
        }

        List<String> results = new ArrayList<>();

        for (JsonNode vulnerability : vulnerabilities) {

            if (!vulnerability.isObject()) {
                continue;
            }

            String id = text(vulnerability, "id");
            String title = text(vulnerability, "title");
            String severity = text(vulnerability, "severity");
            String packageName = text(vulnerability, "packageName");
            String version = text(vulnerability, "version");
            String description = text(vulnerability, "description");

            // Le score CVSS peut être absent du rapport.
            String cvssScore = text(vulnerability, "cvssScore");

            // Chemin de dépendance, lorsqu'il est fourni par Snyk.
            String dependencyPath = formatDependencyPath(
                    vulnerability.path("from")
            );

            // Versions corrigées indiquées par Snyk.
            List<String> fixedVersions = new ArrayList<>();
            JsonNode fixedIn = vulnerability.path("fixedIn");

            if (fixedIn.isArray()) {
                for (JsonNode fixedVersion : fixedIn) {
                    if (fixedVersion != null
                            && !fixedVersion.isNull()
                            && !fixedVersion.asText().isBlank()) {

                        fixedVersions.add(fixedVersion.asText());
                    }
                }
            }

            // Premier CVE disponible, s'il existe.
            String cve = "";
            JsonNode cves = vulnerability
                    .path("identifiers")
                    .path("CVE");

            if (cves.isArray() && !cves.isEmpty()) {
                cve = cves.get(0).asText();
            }

            String summary = """
                    Identifiant Snyk : %s
                    CVE : %s
                    Dépendance : %s
                    Version détectée : %s
                    Sévérité : %s
                    Score CVSS : %s
                    Titre : %s
                    Description : %s
                    Chemin de dépendance : %s
                    Versions correctives indiquées par Snyk : %s
                    """.formatted(
                    id,
                    cve.isBlank() ? "Non renseigné" : cve,
                    packageName,
                    version,
                    severity,
                    cvssScore,
                    title,
                    description,
                    dependencyPath,
                    fixedVersions.isEmpty()
                            ? "Non indiquées"
                            : String.join(", ", fixedVersions)
            );

            results.add(summary);
        }

        return results;
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);

        return value.isMissingNode() || value.isNull()
                || value.asText().isBlank()
                ? "Non renseigné"
                : value.asText();
    }

    private String formatDependencyPath(JsonNode pathNode) {

        if (!pathNode.isArray() || pathNode.isEmpty()) {
            return "Non renseigné";
        }

        List<String> elements = new ArrayList<>();

        for (JsonNode element : pathNode) {
            if (element != null && !element.isNull()) {
                String value = element.asText();

                if (!value.isBlank()) {
                    elements.add(value);
                }
            }
        }

        return elements.isEmpty()
                ? "Non renseigné"
                : String.join(" -> ", elements);
    }
}
