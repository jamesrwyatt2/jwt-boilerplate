package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    public final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        LOG.info("Token Request for: '{}'", authentication.getName());
        String token = tokenService.generateToken(authentication);
        LOG.info("Token generated: '{}'", token);
        return token;
    }
}
