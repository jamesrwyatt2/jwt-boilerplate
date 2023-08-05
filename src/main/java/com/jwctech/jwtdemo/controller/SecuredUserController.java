package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.service.UserAuthenticationService;
import com.jwctech.jwtdemo.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
public class SecuredUserController {

    public final UserAuthenticationService userAuthService;

    public SecuredUserController(UserAuthenticationService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @GetMapping("/secured/user")
    public String secured( @RequestHeader(name="Authorization") String token) {
        User user = getUserFromToken(token);
        return "Welcome to the secured page, " + user.getUsername() + ", Roles: " + user.getRoles();
    }

    public User getUserFromToken(String token) {
        String[] tokenSplit = token.split(" ");
        return userAuthService.findByToken(tokenSplit[1]);
    }
}
