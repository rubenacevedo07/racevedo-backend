package com.acevedo.security.cart;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "https://racevedo.net", allowCredentials = "true")
@RequestMapping("/api/v1/cart")
@RequiredArgsConstructor
public class CartController {
    private final CartService service;

    @PostMapping("/edit")
    public ResponseEntity<Boolean> editItem(@RequestBody CartItem item) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return ResponseEntity.ok(service.editItem(item));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/delete")
    public ResponseEntity<Boolean> deleteItem(@RequestBody CartItem item) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return ResponseEntity.ok(service.deleteItem(item));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/add")
    public ResponseEntity<Number> save(@RequestBody Cart request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            request.setUserEmail(userDetails.getUsername());
            return ResponseEntity.ok(service.addItem(request));
        } else {
            return ResponseEntity.notFound().build(); // Handle unauthenticated user
        }
    }

    @PostMapping("/all")
    public ResponseEntity<List<Cart>> findCartItems() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return ResponseEntity.ok(service.findItems(userDetails.getUsername()));
        } else {
            return ResponseEntity.notFound().build(); // Handle unauthenticated user
        }

    }
}
