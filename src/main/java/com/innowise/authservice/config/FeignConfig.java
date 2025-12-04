package com.innowise.authservice.config;

import com.innowise.authservice.exception.ServiceUnavailableException;
import com.innowise.authservice.exception.UserAlreadyExistsException;
import com.innowise.authservice.exception.UserNotFoundException;
import feign.Logger;
import feign.Request;
import feign.RequestInterceptor;
import feign.Retryer;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@Slf4j
public class FeignConfig {

    @Value("${service.api.key:service-key}")
    private String apiKey;

    @Bean
    public Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

    @Bean
    public RequestInterceptor requestInterceptor() {
        return requestTemplate -> {
            requestTemplate.header("X-Service-Key", apiKey);
            requestTemplate.header("X-Service-Name", "auth-service");
            requestTemplate.header("Content-Type", "application/json");

            log.debug("Feign request to: {} {}",
                    requestTemplate.method(), requestTemplate.url());
        };
    }

    @Bean
    public ErrorDecoder errorDecoder() {
        return (methodKey, response) -> {
            int status = response.status();
            String methodName = methodKey.substring(methodKey.lastIndexOf('#') + 1);

            log.error("Feign error: method={}, status={}, reason={}",
                    methodName, status, response.reason());

            return switch (status) {
                case 404 -> new UserNotFoundException("User not found in User Service");
                case 409 -> new UserAlreadyExistsException("User with this email already exists in User Service");
                case 500 -> new ServiceUnavailableException("User Service encountered an error: " + response.reason());
                default -> new ErrorDecoder.Default().decode(methodKey, response);
            };
        };
    }

    @Bean
    public Request.Options requestOptions() {
        return new Request.Options(
                5000, TimeUnit.MILLISECONDS,
                10000, TimeUnit.MILLISECONDS,
                true
        );
    }

    @Bean
    public Retryer retryer() {
        return new Retryer.Default(
                100,
                1000,
                3
        );
    }
}
