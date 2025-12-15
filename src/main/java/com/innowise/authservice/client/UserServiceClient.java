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

    @PostMapping("/api/v1/users")
    UserInfoDto createUser(@RequestBody CreateUserRequest request);

    @GetMapping("/api/v1/users/by-email/{email}")
    UserInfoDto getUserByEmail(@PathVariable("email") String email);

    @DeleteMapping("/api/v1/users/{id}")
    ResponseEntity<Void> deleteUser(@PathVariable("id") Long id);
}
