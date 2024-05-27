package com.acevedo.security.auth;

import com.acevedo.security.token.TokenDeleteResponse;
import com.acevedo.security.token.TokenRequest;
import com.acevedo.security.token.TokenRevokeResquest;
import com.acevedo.security.user.UserRequest;
import com.acevedo.security.user.UserSignUp;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  @Autowired
  private final AuthenticationService service;


  @CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
  @PostMapping("/validate")
  public ResponseEntity<AuthenticationResponse>validate(@CookieValue(name="accessToken", required=false) String jwt,
                                                        @RequestBody UserRequest user)
  {
    String field1 = user.getUsername();
    if(jwt == null){
      return new ResponseEntity<>(HttpStatus.CONFLICT);
    }
    var response = service.validateSession(jwt, user);
    if (response.valid){
      return ResponseEntity.ok(response);
    }else{
      // You can customize the ResponseEntity as needed
      HttpHeaders headers = new HttpHeaders();
      // Return ResponseEntity with a status code, headers, and response body
      return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
    }

  }

  @CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
  @PostMapping("/sign-in-with-token")
  public ResponseEntity<AuthenticationResponse>tokenValidation(@RequestBody TokenRequest jwt)
  {
    if(jwt == null){
      return new ResponseEntity<>(HttpStatus.CONFLICT);
    }
    var response = service.validateToken(jwt.getAccessToken());
    if (response.valid){
      return ResponseEntity.ok(response);
    }else{
      // You can customize the ResponseEntity as needed
      HttpHeaders headers = new HttpHeaders();
      // Return ResponseEntity with a status code, headers, and response body
      return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
    }

  }

  @CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
  @PostMapping("/login")
  public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request, HttpServletResponse res) {
        AuthenticationResponse auth;
        auth = service.login(request);

        ResponseCookie tokenCookie = ResponseCookie.from("accessToken", auth.getAccessToken())
              .httpOnly(false)  // Flag for security, prevents client-side JavaScript access
              .secure(false)  // Set to true if using HTTPS only.sameSite("none")  // sameSite
              .path("/")  // Accessible from all paths
              .build();

        res.setHeader(HttpHeaders.SET_COOKIE, tokenCookie.toString());

        // Set CSRF token in response header for client-side usage
        //res.setHeader("X-CSRF-TOKEN", service.generateCsrfToken());// CSRF Protection (Example using a hidden form field)

        return ResponseEntity.ok(auth);
    }

  @CrossOrigin(origins = "http://localhost:4200")
  @PostMapping("/forgot-password")
  public ResponseEntity<Boolean> checkEmail(@RequestBody PasswordRequest email) {
    if (service.checkEmail(email)) {
      return ResponseEntity.ok(true);  // Return true in the body for successful email check
    } else {
      return ResponseEntity.notFound().build();  // Use notFound for email not found
    }
  }

  @CrossOrigin(origins = "http://localhost:4200")
  @PostMapping("/reset-password")
  public ResponseEntity<Boolean> resetPassword(@RequestBody ResetPasswordRequest request) {
    // Validate token and update password
    System.out.println("Validate token and update password");
    if (service.validateAndResetPassword(request.getToken(), request.getNewPassword())) {
      return ResponseEntity.ok(true);
    } else {
      return ResponseEntity.badRequest().build();
    }
  }

  @CrossOrigin
  @PostMapping("/register")
  public ResponseEntity<UserSignUp> register(
          @RequestBody RegisterRequest request
  )  throws MessagingException, UnsupportedEncodingException {
    return ResponseEntity.ok(service.register(request));
  }

  @CrossOrigin
  @PostMapping("/revoke-token")
  public ResponseEntity<TokenDeleteResponse> revokeUserToken (
      @RequestBody TokenRevokeResquest request
  ) {
    return ResponseEntity.ok(service.revokeUserToken(request));
  }

  @CrossOrigin
  @GetMapping("/token-authentication")
  public void tokenAuthentication(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    service.tokenAccess(request, response);
  }

  @CrossOrigin
  @GetMapping("/refresh-token")
  public void refreshToken(
      HttpServletRequest request,
      HttpServletResponse response
  ) throws IOException {
    service.refreshToken(request, response);
  }




}
