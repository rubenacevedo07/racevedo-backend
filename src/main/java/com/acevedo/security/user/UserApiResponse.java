package com.acevedo.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class UserApiResponse {

  private String name;
  private String firstName;
  private String lastName;
  private String email;
  private String avatar;
  private String status;
  private boolean enabled;
  @Column(name = "verification", length = 64)
  private String verification;
  private Number counter;

  public UserApiResponse() {

  }
}
