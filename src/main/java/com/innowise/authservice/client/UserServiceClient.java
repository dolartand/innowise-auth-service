package com.innowise.authservice.client;

import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.UserInfoDto;
import com.innowise.authservice.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@FeignClient(
        name = "user-service",
        url = "${user.service.url}",
        configuration = FeignConfig.class
)
public interface UserServiceClient {

    @PostMapping("/internal/users")
    UserInfoDto createUser(@RequestBody CreateUserRequest request);

    @GetMapping("/internal/users/by-email")
    UserInfoDto getUserByEmail(@RequestParam("email") String email);

    @DeleteMapping("/internal/users/{id}")
    ResponseEntity<Void> deleteUser(@PathVariable("id") Long id);
}
