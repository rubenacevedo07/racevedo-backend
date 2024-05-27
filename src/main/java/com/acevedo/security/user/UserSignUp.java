package com.acevedo.security.user;

import com.acevedo.security.user.UserApiResponse;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserSignUp {
    public Boolean valid;
    @JsonProperty("errorMessage")
    private String errorMessage;

}
