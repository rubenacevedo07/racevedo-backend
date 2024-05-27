package com.acevedo.security.cart;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

@Data
@Builder
@AllArgsConstructor
@Entity
@Table(name = "cart")
public class Cart {
    @Id
    @GeneratedValue
    private Integer id;
    private Integer userid;
    private String  userEmail;
    private Integer productid;
    private String  productname;
    private String  photo;
    private Integer quantity;
    private Integer price;
    private BigDecimal subtotal;

    public Cart() {
        // Optional: Initialize default values for fields if needed
    }
}
