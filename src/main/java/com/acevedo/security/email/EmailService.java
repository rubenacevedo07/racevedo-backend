package com.acevedo.security.email;

import com.acevedo.security.user.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    @Autowired
    private JavaMailSender javaMailSender;

    private Environment env;
    @Async
    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("rubenacevedo07@gmail.com");
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        javaMailSender.send(message);
    }

    public EmailService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    @Async
    public void sendVerificationEmail(User user) {

        try {
            String content = "Dear [[name]],<br>"
                    + "Please click the link below to verify your registration:<br>"
                    + "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>"
                    + "Thank you,<br>"
                    + "Your company name.";
            content = content.replace("[[name]]", user.getLastname());
            String verifyURL = "https://racevedo.net/verify?code=" + user.getVerification();

            content = content.replace("[[URL]]", verifyURL);


            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom("rubenacevedo07@gmail.com");
            helper.setTo(user.getEmail());
            helper.setSubject("Please verify your registration");
            content = content.replace("[[name]]", user.getLastname());
            content = content.replace("[[URL]]", verifyURL);
            helper.setText(content, true);
            javaMailSender.send(message);
        } catch (MessagingException e) {
            // Handle the exception or log it
            e.printStackTrace();
        }

    }

    @Async
    public void sendPasswordResetEmail(User user, String token) {

        try {
            String content = buildPasswordResetEmailContent(user, token);

            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom("your_email@example.com");  // Replace with your sender email
            helper.setTo(user.getEmail());
            helper.setSubject("Password Reset Request");
            helper.setText(content, true);
            javaMailSender.send(message);
        } catch (MessagingException e) {
            // Handle the exception or log it
            e.printStackTrace();
        }
    }

    private String buildPasswordResetEmailContent(User user, String token) {
        String baseUrl = "http://localhost:4200"; // Replace with your app's base URL
        String resetUrl = baseUrl + "/reset-password?token=" + token;

        StringBuilder content = new StringBuilder();
        content.append("Dear ").append(user.getLastname()).append(",<br>");
        content.append("You recently requested to reset your password for your account on ").append(baseUrl).append("<br>");
        content.append("Click the link below to reset your password:<br>");
        content.append("<h3><a href=\"").append(resetUrl).append("\" target=\"_self\">RESET PASSWORD</a></h3>");
        content.append("This link will expire within [duration] hours.<br>"); // Specify expiration duration
        content.append("If you did not request a password reset, please ignore this email.<br>");
        content.append("Thank you,<br>");
        content.append("Your Company Name");

        return content.toString();
    }
}
