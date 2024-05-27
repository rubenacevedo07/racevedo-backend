package com.acevedo.security.auth;

import com.acevedo.security.email.EmailService;
import com.acevedo.security.cart.CartRepositoryJpa;
import com.acevedo.security.config.JwtService;
import com.acevedo.security.token.*;
import com.acevedo.security.user.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    @Autowired
    private final UserRepository repository;
    @Autowired
    private final CartRepositoryJpa cartRepository;
    @Autowired
    private final TokenRepository tokenRepository;
    @Autowired
    private final JwtService jwtService;
    @Autowired
    private final AuthenticationManager authenticationManager;
    @Autowired
    private final PasswordResetTokenService passwordResetTokenService;
    @Autowired
    private EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public UserSignUp register(RegisterRequest request) {
        // 1. Validate request fields (optional)
        if (request.getFirstname() == null || request.getFirstname().isEmpty()) {
            return UserSignUp.builder()
                    .valid(false)
                    .errorMessage("Firstname cannot be empty")
                    .build();
        }

        // 2. Check for existing email
        String randomCode = RandomString.make(64);
        Boolean checkResult = repository.verifyEmail(request.getEmail());
        if (checkResult == true) {
            return UserSignUp.builder()
                    .valid(false)
                    .errorMessage("Email already exists")
                    .build();
        }

        // 3. Handle potential password encoding exceptions
        try {
            String encodedPassword = passwordEncoder.encode(request.getPassword());
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(encodedPassword)
                    .role(request.getRole())
                    .verification(randomCode)
                    .build();
            repository.save(user);
        } catch (Error e) {
            return UserSignUp.builder()
                    .valid(false)
                    .errorMessage("Error: " + e.getMessage())
                    .build();
        }

        // 4. Handle potential repository save exceptions (optional)
        // Consider logging the exception details for debugging
        // You might want to retry the save operation or provide a generic error message

        return UserSignUp.builder()
                .valid(true) // Assuming successful registration if no exceptions occurred
                .build();
    }

    public boolean checkEmail(PasswordRequest request) {
        Boolean checkResult = repository.verifyEmail(request.email);
        if (checkResult == false) {
            return false;
        } else {
            var user = repository.findByEmail(request.email).orElseThrow();
            var token = passwordResetTokenService.generateToken(user);
            emailService.sendPasswordResetEmail(user, token);
            return true;
        }
    }

    public Boolean validate(String jwtToken) {
        if (jwtService.isTokenExpired(jwtToken)) {
            return true;
        }
        return false;
    }

    public String generateCsrfToken() {
        SecureRandom random = new SecureRandom();
        // Generate a random byte array of appropriate length (e.g., 32 bytes)
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        // Base64 encode the bytes for a URL-safe string representation
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    public AuthenticationResponse validateSession(String jwtToken, UserRequest userRequest) {
        String field1 = userRequest.getUsername();
        var user = repository.findByEmail(field1).orElseThrow();
        if (jwtService.isTokenValid(jwtToken, user)) {
            UserApiResponse userApiResponse = new UserApiResponse();
            userApiResponse.setAvatar("assets/images/avatars/luke.jpg");
            userApiResponse.setEmail(user.getUsername());
            userApiResponse.setCounter(cartRepository.countItems(user.getUsername()));
            userApiResponse.setStatus("online");
            userApiResponse.setName(user.getFirstname() + " " + user.getLastname());
            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .user(userApiResponse)
                    .valid(true)
                    .build();
        }
        return AuthenticationResponse.builder()
                .accessToken(null)
                .valid(false)
                .build();
    }

    public AuthenticationResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        UserApiResponse userApiResponse = new UserApiResponse();
        userApiResponse.setCounter(cartRepository.countItems(user.getUsername()));
        userApiResponse.setAvatar("assets/images/avatars/luke.jpg");
        userApiResponse.setEmail(request.getEmail());
        userApiResponse.setStatus("online");
        userApiResponse.setName(user.getFirstname() + " " + user.getLastname());

        if (request.getRememberMe() == false) {
            return AuthenticationResponse.builder()
                    .accessToken(null)
                    .user(userApiResponse)
                    .build();
        } else {
            var jwtToken = jwtService.generateToken(user);
            if (jwtService.isTokenValid(jwtToken, user)) {
                saveUserToken(user, jwtToken);
                return AuthenticationResponse.builder()
                        .accessToken(jwtToken)
                        .user(userApiResponse)
                        .build();
            } else {
                return AuthenticationResponse.builder()
                        .accessToken(null)
                        .valid(null)
                        .build();
            }

        }

    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public TokenDeleteResponse revokeUserToken(TokenRevokeResquest request) {

        final String tokenToRevoke = request.getToken();

        var token = tokenRepository.findToken(tokenToRevoke);
        token.setExpired(true);
        token.setRevoked(true);
        tokenRepository.save(token);

        var tokenResponse = TokenDeleteResponse.builder()
                .revoked(true)
                .build();
        return tokenResponse;
    }

    public boolean validateAndResetPassword(String token, String newPassword) {
        // Validate token (check association with user and expiry)
        User user = passwordResetTokenService.validatePasswordResetToken(token);
        System.out.println(token);
        System.out.println(newPassword);
        System.out.println(user.getEmail());

        // Handle the Optional object based on its value (present or empty)
        if (user != null) {
            System.out.println("Validate token true");
            // User found, proceed with password reset logic
            passwordResetTokenService.resetPassword(user, newPassword);
            System.out.println("Validate token true");
            return true;
        } else {
            System.out.println("Validate token false");
            return false;
        }
    }

    public AuthenticationResponse validateToken(String jwtToken) {
        String userEmail;
        String accessToken;
        UserApiResponse userApiResponse = new UserApiResponse();

        String utf8String = new String(jwtToken.getBytes(Charset.forName("windows-1252")), StandardCharsets.UTF_8); // Replace "windows-1252" with the actual encoding
        userEmail = jwtService.extractUsername(utf8String);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            userApiResponse.setCounter(cartRepository.countItems(user.getUsername()));
            userApiResponse.setAvatar("assets/images/avatars/luke.jpg");
            userApiResponse.setEmail(userEmail);
            userApiResponse.setStatus("online");
            userApiResponse.setName(user.getFirstname() + " " + user.getLastname());

            if (jwtService.isTokenValid(utf8String, user)) {
                return AuthenticationResponse.builder()
                        .accessToken(jwtToken)
                        .user(userApiResponse)
                        .valid(true)
                        .build();
            }
        }
        return AuthenticationResponse.builder()
                .accessToken(null)
                .valid(false)
                .build();
    }

    //tokenAccess
    public void tokenAccess(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        String userEmail;
        String accessToken;

        UserApiResponse userApiResponse = new UserApiResponse();

        accessToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(accessToken);

        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            userApiResponse.setAvatar("assets/images/avatars/luke.jpg");
            userApiResponse.setEmail(userEmail);
            userApiResponse.setStatus("online");
            userApiResponse.setName(user.getFirstname() + " " + user.getLastname());

            if (jwtService.isTokenValid(accessToken, user)) {
                var authResponse = TokenAuthResponse.builder()
                        .userApiResponse(userApiResponse)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

    /*if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      // Handle the case where the Authorization header is missing or not in the expected format
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Authorization header");
      return;
    }*/

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        UserApiResponse userApiResponse = new UserApiResponse();

        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);

                userApiResponse.setAvatar("assets/images/avatars/luke.jpg");
                userApiResponse.setEmail(userEmail);
                userApiResponse.setStatus("online");
                userApiResponse.setName(user.getFirstname() + " " + user.getLastname());

                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .user(userApiResponse)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            } else {
                // Handle the case where the token is invalid
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
            }
        }
    }
}
