package com.acevedo.security.order;

import com.acevedo.security.order.order_products.OrderProduct;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@Entity
@Table(name = "orders")
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @JsonIgnore
    private String userEmail;
    private BigInteger total;
    @Column(name = "product_counter")
    private Integer productCounter;
    @Column
    private LocalDateTime orderDateTime;

    @OneToMany(mappedBy = "order", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true ) // Order is the owning side
    @JsonManagedReference
    private List<OrderProduct> orderProducts = new ArrayList<>();
    public Order() {
        // Optional: Initialize default values for fields if needed
    }
}
