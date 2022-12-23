package com.jwctech.jwtdemo.repository;

import com.jwctech.jwtdemo.entity.InvalidToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface InvalidTokenRepository extends JpaRepository<InvalidToken, Long> {

    InvalidToken findByRevokedToken(String token);

}
