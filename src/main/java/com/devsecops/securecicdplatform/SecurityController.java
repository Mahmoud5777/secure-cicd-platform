
package com.devsecops.securecicdplatform;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class SecurityController {

    @GetMapping("/api/status")
    public Map<String, String> getStatus() {
        return Map.of(
                "application", "secure-cicd-platform",
                "status", "UP",
                "security", "DevSecOps"
        );
    }
}
