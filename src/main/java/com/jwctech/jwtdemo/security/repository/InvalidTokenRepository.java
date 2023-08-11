package com.jwctech.jwtdemo.security.repository;

import com.jwctech.jwtdemo.security.models.InvalidToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvalidTokenRepository extends JpaRepository<InvalidToken, Long> {

    InvalidToken findByRevokedToken(String token);

}
