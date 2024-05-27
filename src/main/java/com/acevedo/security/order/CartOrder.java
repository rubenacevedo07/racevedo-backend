package com.acevedo.security.order;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.acevedo.security.cart.Cart;

import java.math.BigInteger;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CartOrder {
    @JsonProperty("cart")
    private List<Cart> cart;
    @JsonProperty("total")
    private BigInteger total;
    @JsonProperty("counter")
    private Integer counter;

}
