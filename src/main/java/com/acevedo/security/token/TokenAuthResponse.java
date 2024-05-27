package com.acevedo.security.token;

import com.acevedo.security.user.UserApiResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenAuthResponse {
  private UserApiResponse userApiResponse;
}

