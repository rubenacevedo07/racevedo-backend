package com.acevedo.security.user;

import com.acevedo.security.auth.ChangePasswordRequest;
import com.acevedo.security.auth.ResetPasswordRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {


    private final UserService service;

    @PatchMapping
    public ResponseEntity<?> changePassword(
          @RequestBody ChangePasswordRequest request,
          Principal connectedUser
    ) {
        service.changePassword(request, connectedUser);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/view")
    public ResponseEntity<UserApiResponse> viewUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            UserApiResponse user = service.getUser(userDetails.getUsername());
            return ResponseEntity.ok(user);
        } else {
            return (ResponseEntity<UserApiResponse>) ResponseEntity.status(HttpStatus.UNAUTHORIZED); // Handle unauthenticated user
        }
    }

    @PostMapping("/edit")
    public ResponseEntity<Boolean> editUser(@RequestBody UserRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            request.setUsername(userDetails.getUsername());
            service.editUser(request);
            return ResponseEntity.ok(Boolean.TRUE);
        } else {
            return ResponseEntity.notFound().build();
        }
    }


    @GetMapping("/verify")
    public String verifyUser(@Param("code") String code) {
        if (service.verify(code)) {
            return "verify_success" + code;
        } else {
            return "verify_fail" + code;
        }
    }


}
