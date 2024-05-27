package com.acevedo.security.cart;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CartItem {
    @JsonProperty("id")
    private Integer id;
    @JsonProperty("quantity")
    private Integer quantity;
}


