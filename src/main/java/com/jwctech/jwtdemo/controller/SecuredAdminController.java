package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.entity.User;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

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
        User user = userAuthService.findByToken(tokenSplit[1]);
        return user;
    }
}
