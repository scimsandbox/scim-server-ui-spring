package de.palsoftware.scim.server.ui;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = "de.palsoftware.scim.server.ui")
@EntityScan(basePackages = "de.palsoftware.scim.server.ui.model")
@EnableJpaRepositories(basePackages = "de.palsoftware.scim.server.ui.repository")
public class ScimServerManagementApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScimServerManagementApplication.class, args);
    }
}
