package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.entity.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    public final UserAuthenticationService userAuthService;

    public HomeController(UserAuthenticationService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to the home page";
    }

    @GetMapping("/secured/user")
    public String secured( @RequestHeader(name="Authorization") String token) {
        User user = getUserFromToken(token);
    return "Welcome to the secured page, " + user.getUsername();
    }

    /**
     * Extracts the user from the token
     * @param token
     * @return
     */
    public User getUserFromToken(String token) {
        String[] tokenSplit = token.split(" ");
        User user = userAuthService.findByToken(tokenSplit[1]);
        return user;
    }
}
