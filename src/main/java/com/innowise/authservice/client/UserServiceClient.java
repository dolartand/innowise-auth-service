package com.innowise.authservice.client;

import com.innowise.authservice.client.dto.UserInfoDto;
import com.innowise.authservice.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "user-service",
        url = "${user.service.url}",
        configuration = FeignConfig.class
)
public interface UserServiceClient {

    @GetMapping("/api/v1/users/{id}")
    UserInfoDto getUserById(@PathVariable("id") Long id);

    @PostMapping("/api/v1/users")
    UserInfoDto createUser(@RequestBody CreateUserRequest request);
}
