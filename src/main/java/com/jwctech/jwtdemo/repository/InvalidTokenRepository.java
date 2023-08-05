package com.jwctech.jwtdemo.repository;

import com.jwctech.jwtdemo.models.InvalidToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvalidTokenRepository extends JpaRepository<InvalidToken, Long> {

    InvalidToken findByRevokedToken(String token);

}
