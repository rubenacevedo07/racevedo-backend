package com.acevedo.security.auth;

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
public class AuthenticationResponse {

  @JsonProperty("accessToken")
  private String accessToken;
  @JsonProperty("refresh_token")
  private String refreshToken;

  private UserApiResponse user;
  public Boolean valid;
}
