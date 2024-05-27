package com.acevedo.security.user;

import com.acevedo.security.auth.ChangePasswordRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final PasswordEncoder passwordEncoder;
    @Autowired
    private final UserRepository repository;
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        // check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }

        // update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // save the new password
        repository.save(user);
    }

    public boolean verify(String verificationCode) {
        User user = repository.findByVerificationCode(verificationCode);
        System.out.println(user.getLastname());
        if (user == null) {
            System.out.println("false");
            return false;
        } else {
            user.setVerification(null);
            user.setEnabled(true);
            repository.save(user);

            return true;
        }
    }

    public UserApiResponse getUser (String userEmail){
        try {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow(() -> new UserNotFoundException("User not found with email: " + userEmail));

            UserApiResponse userResponse = new UserApiResponse();
            userResponse.setAvatar("assets/images/avatars/luke.jpg");
            userResponse.setEmail(userEmail);
            userResponse.setStatus("online");
            userResponse.setFirstName(user.getFirstname());
            userResponse.setLastName(user.getLastname());
            return userResponse;
        } catch (UserNotFoundException e) {
            logger.error("Error fetching user with email: {}", userEmail, e);
            // Handle the exception as needed, such as rethrowing, returning a default response, etc.
            throw e; // or return a default response
        } catch (Exception e) {
            logger.error("An unexpected error occurred while fetching user with email: {}", userEmail, e);
            // Handle the exception as needed, such as rethrowing, returning a default response, etc.
            throw new RuntimeException("An unexpected error occurred"); // or return a default response
        }
    }
    @Transactional
    public void editUser (UserRequest user){
        this.repository.updateByUsername(user.getUsername(), user.getFirstName(), user.getLastName());
    }

    public class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }
}
