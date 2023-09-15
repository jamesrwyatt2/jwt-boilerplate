package com.jwctech.jwtdemo.security.controller;

import com.jwctech.jwtdemo.security.models.User;
import com.jwctech.jwtdemo.security.service.UserAuthenticationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class SecuredAdminController {

    public final UserAuthenticationService userAuthService;

    public SecuredAdminController(UserAuthenticationService userAuthService) {
        this.userAuthService = userAuthService;
    }


    @GetMapping("/secured/admin")
    public String secured( @RequestHeader(name="Authorization") String token) {
        User user = getUserFromToken(token);
        return "Welcome to the secured page, " + user.getUsername();
    }

    public User getUserFromToken(String token) {
        String[] tokenSplit = token.split(" ");
        return userAuthService.findByToken(tokenSplit[1]);
    }
}
