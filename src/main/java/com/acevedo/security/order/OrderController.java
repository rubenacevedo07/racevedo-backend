package com.acevedo.security.order;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "https://racevedo.net", allowCredentials = "true")
@RequestMapping("/api/v1/order")
@RequiredArgsConstructor
public class OrderController {
    @Autowired
    private final OrderService orderService;

    @PostMapping("/add")
    public ResponseEntity<Boolean> createOrder(@RequestBody CartOrder cartOrder) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            orderService.createOrder(userDetails.getUsername(), cartOrder);
            return ResponseEntity.ok(Boolean.TRUE);
        } else {
            return ResponseEntity.notFound().build(); // Handle unauthenticated user
        }
    }
    @PostMapping("/all")
    public ResponseEntity<List<Order>> getOrdersByUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return ResponseEntity.ok(orderService.findOrdersItemsByUser(userDetails.getUsername()));
        } else {
            return ResponseEntity.notFound().build(); // Handle unauthenticated user
        }
    }
}

