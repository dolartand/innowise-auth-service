package com.innowise.authservice.integration;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@ExtendWith(MockitoExtension.class)
public class BaseIntegrationTest {

    @Container
    protected static final PostgreSQLContainer<?> postgreSQLContainer =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"))
                    .withDatabaseName("testdb")
                    .withUsername("test")
                    .withPassword("test")
                    .withReuse(true);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgreSQLContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgreSQLContainer::getUsername);
        registry.add("spring.datasource.password", postgreSQLContainer::getPassword);

        registry.add("spring.liquibase.enabled", () -> "true");

        registry.add("jwt.secret", () -> "dmVyeS12ZXJ5LXZlcnktbG9uZy1zZWNyZXQta2V5LWZvci10ZXN0aW5nLXB1cnBvc2VzLXRoYXQtaXMtZGVmaW5pdGVseS1tb3JlLXRoYW4tNjQtYnl0ZXMtbG9uZy10by1zYXRpc2Z5LWhzNTEy");
        registry.add("jwt.access-token-expiration", () -> "900000");
        registry.add("jwt.refresh-token-expiration", () -> "2592000000");
        registry.add("jwt.issuer", () -> "auth-service-test");
    }
}