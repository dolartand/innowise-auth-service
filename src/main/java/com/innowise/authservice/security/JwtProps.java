package com.innowise.authservice.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProps {

    @NotBlank(message = "JWT secret is required")
    private String secret;

    @NotNull(message = "Access token is required")
    private Long accessTokenExpiration;

    @NotNull(message = "Refresh token is required")
    private Long refreshTokenExpiration;

    @NotBlank(message = "Issuer is required")
    private String issuer;
}
