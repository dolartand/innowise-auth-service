package com.innowise.authservice.service.impl;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.UserInfoDto;
import com.innowise.authservice.dto.*;
import com.innowise.authservice.entity.RefreshToken;
import com.innowise.authservice.entity.UserCredential;
import com.innowise.authservice.enums.Role;
import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.UserAlreadyExistsException;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.repository.UserCredentialRepository;
import com.innowise.authservice.security.JwtProps;
import com.innowise.authservice.security.JwtTokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService unit tests")
public class AuthenticationServiceImplTest {

    @Mock
    private UserServiceClient userServiceClient;

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private JwtProps jwtProps;

    @InjectMocks
    private AuthenticationServiceImpl authenticationService;

    @Nested
    @DisplayName("register tests")
    class RegisterTests {

        @Test
        @DisplayName("should successfully register new user")
        void shouldRegisterNewUser_Success() {
            RegisterRequest request = createRegisterRequest();
            UserInfoDto createdUser = createUserInfoDto();

            when(userCredentialRepository.existsByEmail(request.email())).thenReturn(false);
            when(userServiceClient.createUser(any(CreateUserRequest.class))).thenReturn(createdUser);
            when(passwordEncoder.encode(request.password())).thenReturn("encoded_password");
            when(userCredentialRepository.count()).thenReturn(1L); // Не первый пользователь
            when(jwtTokenProvider.generateAccessToken(anyLong(), anyString(), any(Role.class)))
                    .thenReturn("access_token");
            when(jwtTokenProvider.generateRefreshToken(anyLong())).thenReturn("refresh_token");
            when(jwtProps.getAccessTokenExpiration()).thenReturn(900000L);

            AuthResponse response = authenticationService.register(request);

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo("access_token");
            assertThat(response.refreshToken()).isEqualTo("refresh_token");
            assertThat(response.userId()).isEqualTo(createdUser.id());
            assertThat(response.email()).isEqualTo(request.email());
            assertThat(response.role()).isEqualTo("USER");

            ArgumentCaptor<UserCredential> credentialCaptor = ArgumentCaptor.forClass(UserCredential.class);
            verify(userCredentialRepository).save(credentialCaptor.capture());
            UserCredential savedCredential = credentialCaptor.getValue();
            assertThat(savedCredential.getEmail()).isEqualTo(request.email());
            assertThat(savedCredential.getRole()).isEqualTo(Role.USER);

            verify(refreshTokenRepository).deleteByUserId(createdUser.id());
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("should assign ADMIN role to first user")
        void shouldAssignAdminRoleToFirstUser() {
            RegisterRequest request = createRegisterRequest();
            UserInfoDto createdUser = createUserInfoDto();

            when(userCredentialRepository.existsByEmail(request.email())).thenReturn(false);
            when(userServiceClient.createUser(any(CreateUserRequest.class))).thenReturn(createdUser);
            when(passwordEncoder.encode(request.password())).thenReturn("encoded_password");
            when(userCredentialRepository.count()).thenReturn(0L); // Первый пользователь
            when(jwtTokenProvider.generateAccessToken(anyLong(), anyString(), any(Role.class)))
                    .thenReturn("access_token");
            when(jwtTokenProvider.generateRefreshToken(anyLong())).thenReturn("refresh_token");
            when(jwtProps.getAccessTokenExpiration()).thenReturn(900000L);

            AuthResponse response = authenticationService.register(request);

            assertThat(response.role()).isEqualTo("ADMIN");

            ArgumentCaptor<UserCredential> credentialCaptor = ArgumentCaptor.forClass(UserCredential.class);
            verify(userCredentialRepository).save(credentialCaptor.capture());
            assertThat(credentialCaptor.getValue().getRole()).isEqualTo(Role.ADMIN);
        }

        @Test
        @DisplayName("should throw UserAlreadyExistsException when email exists")
        void shouldThrowUserAlreadyExistsException_WhenEmailExists() {
            RegisterRequest request = createRegisterRequest();

            when(userCredentialRepository.existsByEmail(request.email())).thenReturn(true);

            assertThatThrownBy(() -> authenticationService.register(request))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessageContaining("already exists");

            verify(userServiceClient, never()).createUser(any());
            verify(userCredentialRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("login tests")
    class LoginTests {

        @Test
        @DisplayName("should successfully login user")
        void shouldLoginUser_Success() {
            LoginRequest request = createLoginRequest();
            UserCredential credential = createUserCredential();
            UserInfoDto userInfo = createUserInfoDto();

            when(userCredentialRepository.findByEmail(request.email())).thenReturn(Optional.of(credential));
            when(passwordEncoder.matches(request.password(), credential.getPasswordHash())).thenReturn(true);
            when(userServiceClient.getUserById(credential.getUserId())).thenReturn(userInfo);
            when(jwtTokenProvider.generateAccessToken(anyLong(), anyString(), any(Role.class)))
                    .thenReturn("access_token");
            when(jwtTokenProvider.generateRefreshToken(anyLong())).thenReturn("refresh_token");
            when(jwtProps.getAccessTokenExpiration()).thenReturn(900000L);

            AuthResponse response = authenticationService.login(request);

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo("access_token");
            assertThat(response.refreshToken()).isEqualTo("refresh_token");
            assertThat(response.userId()).isEqualTo(credential.getUserId());
            assertThat(response.email()).isEqualTo(credential.getEmail());
            assertThat(response.role()).isEqualTo("USER");

            verify(refreshTokenRepository).deleteByUserId(credential.getUserId());
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("should throw InvalidCredentialsException when user not found")
        void shouldThrowInvalidCredentialsException_WhenUserNotFound() {
            LoginRequest request = createLoginRequest();

            when(userCredentialRepository.findByEmail(request.email())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authenticationService.login(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("Invalid email or password");

            verify(passwordEncoder, never()).matches(anyString(), anyString());
            verify(refreshTokenRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw InvalidCredentialsException when password incorrect")
        void shouldThrowInvalidCredentialsException_WhenPasswordIncorrect() {
            LoginRequest request = createLoginRequest();
            UserCredential credential = createUserCredential();

            when(userCredentialRepository.findByEmail(request.email())).thenReturn(Optional.of(credential));
            when(passwordEncoder.matches(request.password(), credential.getPasswordHash())).thenReturn(false);

            assertThatThrownBy(() -> authenticationService.login(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("Invalid email or password");

            verify(jwtTokenProvider, never()).generateAccessToken(anyLong(), anyString(), any());
            verify(refreshTokenRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw InvalidCredentialsException when user is not active")
        void shouldThrowInvalidCredentialsException_WhenUserNotActive() {
            LoginRequest request = createLoginRequest();
            UserCredential credential = createUserCredential();
            UserInfoDto inactiveUser = UserInfoDto.builder()
                    .id(1L)
                    .name("Ivan")
                    .surname("Ivanov")
                    .birthDate(LocalDate.of(1990, 1, 1))
                    .email("ivan@example.com")
                    .active(false)
                    .build();

            when(userCredentialRepository.findByEmail(request.email())).thenReturn(Optional.of(credential));
            when(passwordEncoder.matches(request.password(), credential.getPasswordHash())).thenReturn(true);
            when(userServiceClient.getUserById(credential.getUserId())).thenReturn(inactiveUser);

            assertThatThrownBy(() -> authenticationService.login(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("Failed");

            verify(jwtTokenProvider, never()).generateAccessToken(anyLong(), anyString(), any());
            verify(refreshTokenRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("refreshAccessToken tests")
    class RefreshAccessTokenTests {

        @Test
        @DisplayName("should successfully refresh access token")
        void shouldRefreshAccessToken_Success() {
            String refreshTokenString = "valid_refresh_token";
            RefreshTokenRequest request = new RefreshTokenRequest(refreshTokenString);
            RefreshToken storedToken = createRefreshToken(refreshTokenString);
            UserCredential credential = createUserCredential();

            when(jwtTokenProvider.validateToken(refreshTokenString)).thenReturn(true);
            when(jwtTokenProvider.getTokenType(refreshTokenString)).thenReturn("refresh");
            when(refreshTokenRepository.findByToken(refreshTokenString)).thenReturn(Optional.of(storedToken));
            when(userCredentialRepository.findByUserId(storedToken.getUserId())).thenReturn(Optional.of(credential));
            when(jwtTokenProvider.generateAccessToken(anyLong(), anyString(), any(Role.class)))
                    .thenReturn("new_access_token");
            when(jwtTokenProvider.generateRefreshToken(anyLong())).thenReturn("new_refresh_token");
            when(jwtProps.getAccessTokenExpiration()).thenReturn(900000L);

            AuthResponse response = authenticationService.refreshAccessToken(request);

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo("new_access_token");
            assertThat(response.refreshToken()).isEqualTo("new_refresh_token");
            assertThat(response.userId()).isEqualTo(credential.getUserId());

            verify(refreshTokenRepository).delete(storedToken);
            verify(refreshTokenRepository).deleteByUserId(credential.getUserId());
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("should throw InvalidTokenException when token is invalid")
        void shouldThrowInvalidTokenException_WhenTokenInvalid() {
            String refreshTokenString = "invalid_token";
            RefreshTokenRequest request = new RefreshTokenRequest(refreshTokenString);

            when(jwtTokenProvider.validateToken(refreshTokenString)).thenReturn(false);

            assertThatThrownBy(() -> authenticationService.refreshAccessToken(request))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid refresh token");

            verify(refreshTokenRepository, never()).findByToken(anyString());
        }

        @Test
        @DisplayName("should throw InvalidTokenException when token type is not refresh")
        void shouldThrowInvalidTokenException_WhenTokenTypeNotRefresh() {
            String accessTokenString = "access_token";
            RefreshTokenRequest request = new RefreshTokenRequest(accessTokenString);

            when(jwtTokenProvider.validateToken(accessTokenString)).thenReturn(true);
            when(jwtTokenProvider.getTokenType(accessTokenString)).thenReturn("access");

            assertThatThrownBy(() -> authenticationService.refreshAccessToken(request))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("not a refresh token");

            verify(refreshTokenRepository, never()).findByToken(anyString());
        }

        @Test
        @DisplayName("should throw InvalidTokenException when token not found in database")
        void shouldThrowInvalidTokenException_WhenTokenNotFoundInDatabase() {
            String refreshTokenString = "unknown_token";
            RefreshTokenRequest request = new RefreshTokenRequest(refreshTokenString);

            when(jwtTokenProvider.validateToken(refreshTokenString)).thenReturn(true);
            when(jwtTokenProvider.getTokenType(refreshTokenString)).thenReturn("refresh");
            when(refreshTokenRepository.findByToken(refreshTokenString)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authenticationService.refreshAccessToken(request))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("not found");

            verify(userCredentialRepository, never()).findByUserId(anyLong());
        }

        @Test
        @DisplayName("should throw InvalidTokenException when token is expired")
        void shouldThrowInvalidTokenException_WhenTokenExpired() {
            String refreshTokenString = "expired_token";
            RefreshTokenRequest request = new RefreshTokenRequest(refreshTokenString);
            RefreshToken expiredToken = RefreshToken.builder()
                    .id(1L)
                    .userId(1L)
                    .token(refreshTokenString)
                    .expiresAt(LocalDateTime.now().minusDays(1))
                    .createdAt(LocalDateTime.now().minusDays(2))
                    .build();

            when(jwtTokenProvider.validateToken(refreshTokenString)).thenReturn(true);
            when(jwtTokenProvider.getTokenType(refreshTokenString)).thenReturn("refresh");
            when(refreshTokenRepository.findByToken(refreshTokenString)).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> authenticationService.refreshAccessToken(request))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("expired");

            verify(refreshTokenRepository).delete(expiredToken);
            verify(userCredentialRepository, never()).findByUserId(anyLong());
        }
    }

    @Nested
    @DisplayName("validateToken tests")
    class ValidateTokenTests {

        @Test
        @DisplayName("should return valid response for valid token")
        void shouldReturnValidResponse_ForValidToken() {
            String validToken = "valid_token";
            TokenValidationRequest request = new TokenValidationRequest(validToken);

            when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);
            when(jwtTokenProvider.isTokenExpired(validToken)).thenReturn(false);
            when(jwtTokenProvider.getUserIdFromToken(validToken)).thenReturn(1L);
            when(jwtTokenProvider.getEmailFromToken(validToken)).thenReturn("ivan@example.com");
            when(jwtTokenProvider.getRoleFromToken(validToken)).thenReturn(Role.USER);

            TokenValidationResponse response = authenticationService.validateToken(request);

            assertThat(response).isNotNull();
            assertThat(response.valid()).isTrue();
            assertThat(response.userId()).isEqualTo(1L);
            assertThat(response.email()).isEqualTo("ivan@example.com");
            assertThat(response.role()).isEqualTo("USER");
            assertThat(response.message()).isNull();
        }

        @Test
        @DisplayName("should return invalid response for invalid token")
        void shouldReturnInvalidResponse_ForInvalidToken() {
            String invalidToken = "invalid_token";
            TokenValidationRequest request = new TokenValidationRequest(invalidToken);

            when(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false);

            TokenValidationResponse response = authenticationService.validateToken(request);

            assertThat(response).isNotNull();
            assertThat(response.valid()).isFalse();
            assertThat(response.message()).isEqualTo("Invalid token");
            assertThat(response.userId()).isNull();
        }

        @Test
        @DisplayName("should return invalid response for expired token")
        void shouldReturnInvalidResponse_ForExpiredToken() {
            String expiredToken = "expired_token";
            TokenValidationRequest request = new TokenValidationRequest(expiredToken);

            when(jwtTokenProvider.validateToken(expiredToken)).thenReturn(true);
            when(jwtTokenProvider.isTokenExpired(expiredToken)).thenReturn(true);

            TokenValidationResponse response = authenticationService.validateToken(request);

            assertThat(response).isNotNull();
            assertThat(response.valid()).isFalse();
            assertThat(response.message()).isEqualTo("Token expired");
        }
    }

    @Nested
    @DisplayName("logout tests")
    class LogoutTests {

        @Test
        @DisplayName("should successfully delete refresh token on logout")
        void shouldDeleteRefreshToken_OnLogout() {
            String refreshTokenString = "refresh_token";
            RefreshToken storedToken = createRefreshToken(refreshTokenString);

            when(refreshTokenRepository.findByToken(refreshTokenString)).thenReturn(Optional.of(storedToken));

            authenticationService.logout(refreshTokenString);

            verify(refreshTokenRepository).findByToken(refreshTokenString);
            verify(refreshTokenRepository).delete(storedToken);
        }

        @Test
        @DisplayName("should not throw exception when token not found on logout")
        void shouldNotThrowException_WhenTokenNotFoundOnLogout() {
            String refreshTokenString = "non_existent_token";

            when(refreshTokenRepository.findByToken(refreshTokenString)).thenReturn(Optional.empty());

            authenticationService.logout(refreshTokenString);

            verify(refreshTokenRepository).findByToken(refreshTokenString);
            verify(refreshTokenRepository, never()).delete(any());
        }
    }

    private RegisterRequest createRegisterRequest() {
        return RegisterRequest.builder()
                .name("Ivan")
                .surname("Ivanov")
                .birthDate(LocalDate.of(1990, 1, 1))
                .email("ivan@example.com")
                .password("Password123")
                .build();
    }

    private LoginRequest createLoginRequest() {
        return LoginRequest.builder()
                .email("ivan@example.com")
                .password("Password123")
                .build();
    }

    private UserInfoDto createUserInfoDto() {
        return UserInfoDto.builder()
                .id(1L)
                .name("Ivan")
                .surname("Ivanov")
                .birthDate(LocalDate.of(1990, 1, 1))
                .email("ivan@example.com")
                .active(true)
                .build();
    }

    private UserCredential createUserCredential() {
        return UserCredential.builder()
                .id(1L)
                .userId(1L)
                .email("ivan@example.com")
                .passwordHash("$2a$12$encoded_password_hash")
                .role(Role.USER)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    private RefreshToken createRefreshToken(String token) {
        return RefreshToken.builder()
                .id(1L)
                .userId(1L)
                .token(token)
                .expiresAt(LocalDateTime.now().plusDays(30))
                .createdAt(LocalDateTime.now())
                .build();
    }
}