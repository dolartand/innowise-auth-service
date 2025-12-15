package com.innowise.authservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.UserInfoDto;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RefreshTokenRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.TokenValidationRequest;
import com.innowise.authservice.entity.RefreshToken;
import com.innowise.authservice.entity.UserCredential;
import com.innowise.authservice.enums.Role;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.repository.UserCredentialRepository;
import com.innowise.authservice.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@DisplayName("AuthController integration tests")
public class AuthControllerIT extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @MockitoBean
    private UserServiceClient userServiceClient;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userCredentialRepository.deleteAll();
    }

    @Nested
    @DisplayName("Test POST /api/v1/auth/register")
    class RegisterTests {

        @Test
        @DisplayName("should successfully register new user")
        void shouldRegisterNewUser_Success() throws Exception {
            RegisterRequest request = createRegisterRequest("ivan@example.com");
            UserInfoDto userInfoDto = createUserInfoDto(1L, "ivan@example.com");

            when(userServiceClient.createUser(any(CreateUserRequest.class))).thenReturn(userInfoDto);

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.accessToken", notNullValue()))
                    .andExpect(jsonPath("$.refreshToken", notNullValue()))
                    .andExpect(jsonPath("$.tokenType").value("Bearer"))
                    .andExpect(jsonPath("$.userId").value(1))
                    .andExpect(jsonPath("$.email").value("ivan@example.com"))
                    .andExpect(jsonPath("$.role").value("ADMIN"));

            List<UserCredential> credentials = userCredentialRepository.findAll();
            assertThat(credentials).hasSize(1);
            assertThat(credentials.getFirst().getEmail()).isEqualTo("ivan@example.com");
            assertThat(credentials.getFirst().getRole()).isEqualTo(Role.ADMIN);

            List<RefreshToken> tokens = refreshTokenRepository.findAll();
            assertThat(tokens).hasSize(1);
        }

        @Test
        @DisplayName("should assign USER role to second user")
        void shouldAssignUserRoleToSecondUser() throws Exception {
            // Создаем первого пользователя (ADMIN)
            createAndSaveUserCredential(1L, "admin@example.com", Role.ADMIN);

            RegisterRequest request = createRegisterRequest("user@example.com");
            UserInfoDto userInfoDto = createUserInfoDto(2L, "user@example.com");

            when(userServiceClient.createUser(any(CreateUserRequest.class))).thenReturn(userInfoDto);

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.role").value("USER"));

            UserCredential userCredential = userCredentialRepository.findByEmail("user@example.com").orElseThrow();
            assertThat(userCredential.getRole()).isEqualTo(Role.USER);
        }

        @Test
        @DisplayName("should return 409 when user with email already exists")
        void shouldReturn409_WhenUserEmailAlreadyExists() throws Exception {
            createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);

            RegisterRequest request = createRegisterRequest("ivan@example.com");

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.message", containsString("already exists")));
        }

        @Test
        @DisplayName("should return 400 when request data is invalid")
        void shouldReturn400_WhenRequestDataInvalid() throws Exception {
            RegisterRequest request = RegisterRequest.builder()
                    .name("Iv")
                    .surname("Ivanov")
                    .birthDate(LocalDate.now().plusDays(1))
                    .email("invalid-email")
                    .password("weak")
                    .build();

            mockMvc.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Test POST /api/v1/auth/login")
    class LoginTests {

        @Test
        @DisplayName("should successfully login user")
        void shouldLoginUser_Success() throws Exception {
            String rawPassword = "Password123";
            UserCredential credential = createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);
            credential.setPasswordHash(passwordEncoder.encode(rawPassword));
            userCredentialRepository.save(credential);

            UserInfoDto userInfoDto = createUserInfoDto(1L, "ivan@example.com");
            when(userServiceClient.getUserByEmail(anyString())).thenReturn(userInfoDto);

            LoginRequest request = LoginRequest.builder()
                    .email("ivan@example.com")
                    .password(rawPassword)
                    .build();

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken", notNullValue()))
                    .andExpect(jsonPath("$.refreshToken", notNullValue()))
                    .andExpect(jsonPath("$.userId").value(1))
                    .andExpect(jsonPath("$.email").value("ivan@example.com"))
                    .andExpect(jsonPath("$.role").value("USER"));

            List<RefreshToken> tokens = refreshTokenRepository.findByUserId(1L);
            assertThat(tokens).hasSize(1);
        }

        @Test
        @DisplayName("should return 401 when user not found")
        void shouldReturn401_WhenUserNotFound() throws Exception {
            LoginRequest request = LoginRequest.builder()
                    .email("nonexistent@example.com")
                    .password("Password123")
                    .build();

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("Invalid email or password")));
        }

        @Test
        @DisplayName("should return 401 when password is incorrect")
        void shouldReturn401_WhenPasswordIncorrect() throws Exception {
            String correctPassword = "Password123";
            UserCredential credential = createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);
            credential.setPasswordHash(passwordEncoder.encode(correctPassword));
            userCredentialRepository.save(credential);

            LoginRequest request = LoginRequest.builder()
                    .email("ivan@example.com")
                    .password("WrongPassword123")
                    .build();

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("Invalid email or password")));
        }

        @Test
        @DisplayName("should return 401 when user is not active")
        void shouldReturn401_WhenUserNotActive() throws Exception {
            String rawPassword = "Password123";
            UserCredential credential = createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);
            credential.setPasswordHash(passwordEncoder.encode(rawPassword));
            userCredentialRepository.save(credential);

            UserInfoDto inactiveUser = UserInfoDto.builder()
                    .id(1L)
                    .name("Ivan")
                    .surname("Ivanov")
                    .birthDate(LocalDate.of(1990, 1, 1))
                    .email("ivan@example.com")
                    .active(false)
                    .build();
            when(userServiceClient.getUserByEmail(anyString())).thenReturn(inactiveUser);

            LoginRequest request = LoginRequest.builder()
                    .email("ivan@example.com")
                    .password(rawPassword)
                    .build();

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("Failed to validate")));
        }

        @Test
        @DisplayName("should replace old refresh token with new on login")
        void shouldReplaceOldRefreshTokenWithNew_OnLogin() throws Exception {
            String rawPassword = "Password123";
            UserCredential credential = createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);
            credential.setPasswordHash(passwordEncoder.encode(rawPassword));
            userCredentialRepository.save(credential);

            RefreshToken oldToken = RefreshToken.builder()
                    .userId(1L)
                    .token("old_refresh_token")
                    .expiresAt(LocalDateTime.now().plusDays(30))
                    .createdAt(LocalDateTime.now())
                    .build();
            refreshTokenRepository.save(oldToken);

            UserInfoDto userInfoDto = createUserInfoDto(1L, "ivan@example.com");
            when(userServiceClient.getUserByEmail(anyString())).thenReturn(userInfoDto);

            LoginRequest request = LoginRequest.builder()
                    .email("ivan@example.com")
                    .password(rawPassword)
                    .build();

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            List<RefreshToken> tokens = refreshTokenRepository.findByUserId(1L);
            assertThat(tokens).hasSize(1);
            assertThat(tokens.getFirst().getToken()).isNotEqualTo("old_refresh_token");
        }
    }

    @Nested
    @DisplayName("Test POST /api/v1/auth/refresh")
    class RefreshTests {

        @Test
        @DisplayName("should successfully refresh access token")
        void shouldRefreshAccessToken_Success() throws Exception {
            UserCredential credential = createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);

            String refreshToken = jwtTokenProvider.generateRefreshToken(1L);
            RefreshToken storedToken = RefreshToken.builder()
                    .userId(1L)
                    .token(refreshToken)
                    .expiresAt(LocalDateTime.now().plusDays(30))
                    .createdAt(LocalDateTime.now())
                    .build();
            refreshTokenRepository.save(storedToken);

            RefreshTokenRequest request = new RefreshTokenRequest(refreshToken);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken", notNullValue()))
                    .andExpect(jsonPath("$.refreshToken", notNullValue()))
                    .andExpect(jsonPath("$.userId").value(1))
                    .andExpect(jsonPath("$.email").value("ivan@example.com"));

            assertThat(refreshTokenRepository.findByUserId(1L)).hasSize(1);
        }

        @Test
        @DisplayName("should return 401 when refresh token is invalid")
        void shouldReturn401_WhenRefreshTokenInvalid() throws Exception {
            RefreshTokenRequest request = new RefreshTokenRequest("invalid_token");

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("Invalid refresh token")));
        }

        @Test
        @DisplayName("should return 401 when refresh token not found in database")
        void shouldReturn401_WhenRefreshTokenNotFoundInDatabase() throws Exception {
            String refreshToken = jwtTokenProvider.generateRefreshToken(1L);
            RefreshTokenRequest request = new RefreshTokenRequest(refreshToken);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("not found")));
        }

        @Test
        @DisplayName("should return 401 when trying to refresh with access token")
        void shouldReturn401_WhenTryingToRefreshWithAccessToken() throws Exception {
            createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);

            String accessToken = jwtTokenProvider.generateAccessToken(1L, "ivan@example.com", Role.USER);
            RefreshTokenRequest request = new RefreshTokenRequest(accessToken);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("not a refresh token")));
        }

        @Test
        @DisplayName("should return 401 when refresh token is expired")
        void shouldReturn401_WhenRefreshTokenExpired() throws Exception {
            createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);

            String refreshToken = jwtTokenProvider.generateRefreshToken(1L);
            RefreshToken expiredToken = RefreshToken.builder()
                    .userId(1L)
                    .token(refreshToken)
                    .expiresAt(LocalDateTime.now().minusDays(1))
                    .createdAt(LocalDateTime.now().minusDays(31))
                    .build();
            refreshTokenRepository.save(expiredToken);

            RefreshTokenRequest request = new RefreshTokenRequest(refreshToken);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message", containsString("expired")));
        }
    }

    @Nested
    @DisplayName("Test POST /api/v1/auth/validate")
    class ValidateTests {

        @Test
        @DisplayName("should return valid response for valid token")
        void shouldReturnValidResponse_ForValidToken() throws Exception {
            String accessToken = jwtTokenProvider.generateAccessToken(1L, "ivan@example.com", Role.USER);
            TokenValidationRequest request = new TokenValidationRequest(accessToken);

            mockMvc.perform(post("/api/v1/auth/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(true))
                    .andExpect(jsonPath("$.userId").value(1))
                    .andExpect(jsonPath("$.email").value("ivan@example.com"))
                    .andExpect(jsonPath("$.role").value("USER"));
        }

        @Test
        @DisplayName("should return invalid response for invalid token")
        void shouldReturnInvalidResponse_ForInvalidToken() throws Exception {
            TokenValidationRequest request = new TokenValidationRequest("invalid_token");

            mockMvc.perform(post("/api/v1/auth/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(false))
                    .andExpect(jsonPath("$.message", containsString("Invalid token")));
        }

        @Test
        @DisplayName("should return invalid response for malformed token")
        void shouldReturnInvalidResponse_ForMalformedToken() throws Exception {
            TokenValidationRequest request = new TokenValidationRequest("malformed.token.here");

            mockMvc.perform(post("/api/v1/auth/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(false));
        }
    }

    @Nested
    @DisplayName("Test POST /api/v1/auth/logout")
    class LogoutTests {

        @Test
        @DisplayName("should successfully logout user")
        void shouldLogoutUser_Success() throws Exception {
            createAndSaveUserCredential(1L, "ivan@example.com", Role.USER);

            String refreshToken = jwtTokenProvider.generateRefreshToken(1L);
            RefreshToken storedToken = RefreshToken.builder()
                    .userId(1L)
                    .token(refreshToken)
                    .expiresAt(LocalDateTime.now().plusDays(30))
                    .createdAt(LocalDateTime.now())
                    .build();
            refreshTokenRepository.save(storedToken);

            RefreshTokenRequest request = new RefreshTokenRequest(refreshToken);

            mockMvc.perform(post("/api/v1/auth/logout")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isNoContent());

            assertThat(refreshTokenRepository.findByToken(refreshToken)).isEmpty();
        }

        @Test
        @DisplayName("should return 204 even when token not found")
        void shouldReturn204_EvenWhenTokenNotFound() throws Exception {
            RefreshTokenRequest request = new RefreshTokenRequest("non_existent_token");

            mockMvc.perform(post("/api/v1/auth/logout")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isNoContent());
        }
    }

    private RegisterRequest createRegisterRequest(String email) {
        return RegisterRequest.builder()
                .name("Ivan")
                .surname("Ivanov")
                .birthDate(LocalDate.of(1990, 1, 1))
                .email(email)
                .password("Password123")
                .build();
    }

    private UserInfoDto createUserInfoDto(Long id, String email) {
        return UserInfoDto.builder()
                .id(id)
                .name("Ivan")
                .surname("Ivanov")
                .birthDate(LocalDate.of(1990, 1, 1))
                .email(email)
                .active(true)
                .build();
    }

    private UserCredential createAndSaveUserCredential(Long userId, String email, Role role) {
        UserCredential credential = UserCredential.builder()
                .userId(userId)
                .email(email)
                .passwordHash(passwordEncoder.encode("Password123"))
                .role(role)
                .build();
        return userCredentialRepository.save(credential);
    }
}