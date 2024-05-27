package com.acevedo.security.auth;

import com.acevedo.security.user.UserApiResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtValidateResponse {
  public Boolean valid;
  private UserApiResponse user;
}
