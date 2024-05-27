package com.acevedo.security.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {
  @JsonProperty("username")
  public String username;
  @JsonProperty("firstName")
  public String firstName;
  @JsonProperty("lastName")
  public String lastName;
}
