package com.acevedo.security.order.order_products;

import com.acevedo.security.cart.Cart;
import com.acevedo.security.order.Order;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;

import java.math.BigDecimal;

@Data
@Builder
@AllArgsConstructor
@Entity
@Table(name = "order_products")
public class OrderProduct {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    private Long id;
    private String name;
    private Integer product_id;
    private Integer price;
    private Integer quantity;
    private BigDecimal subtotal;

    @ManyToOne
    @JoinColumn(name = "order_id")
    @JsonBackReference
    @ToString.Exclude
    private Order order;

    public OrderProduct(Order order, Cart cart) {
        this.order = order;
        this.name = cart.getProductname();
        this.product_id = cart.getProductid();
        this.price = cart.getPrice();
        this.quantity = cart.getQuantity();
        this.subtotal = BigDecimal.valueOf(cart.getPrice()).multiply(BigDecimal.valueOf(cart.getQuantity()));
    }


    public OrderProduct() {
        // Optional: Initialize default values for fields if needed
    }
}
