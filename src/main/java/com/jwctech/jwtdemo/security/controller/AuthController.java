package com.jwctech.jwtdemo.security.controller;

import com.jwctech.jwtdemo.security.exception.TokenRefreshException;
import com.jwctech.jwtdemo.security.jwt.TokenProviderUtil;
import com.jwctech.jwtdemo.security.models.ERole;
import com.jwctech.jwtdemo.security.models.RefreshToken;
import com.jwctech.jwtdemo.security.payload.response.MessageResponse;
import com.jwctech.jwtdemo.security.service.RefreshTokenService;
import com.jwctech.jwtdemo.security.service.UserAuthenticationService;
import com.jwctech.jwtdemo.security.service.UserService;
import com.jwctech.jwtdemo.security.payload.request.AuthRequest;
import com.jwctech.jwtdemo.security.models.Role;
import com.jwctech.jwtdemo.security.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    public final UserService userService;
    public final UserAuthenticationService userAuthService;
    public final RefreshTokenService refreshTokenService;
    public final TokenProviderUtil tokenProviderUtil;

    // Constructor
    public AuthController(UserService userService, UserAuthenticationService userAuthService, TokenProviderUtil tokenProviderUtil, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.userAuthService = userAuthService;
        this.tokenProviderUtil = tokenProviderUtil;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * signIn handles login for current users
     * @param authRequest is user credentials to login
     * @return Cookie for JWT, Cookie for Refresh Token, and body with User details
     */

    @PostMapping(value = "/signin", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity signIn(@RequestBody AuthRequest authRequest) {

        // validate User Credentials
        String token = userAuthService.login(authRequest.username(), authRequest.password());

        // Get User details
        User user = userService.loadUserByUsername(authRequest.username());

        // Create JWT and Cookie
        ResponseCookie jwtCookie = tokenProviderUtil.generateJwtCookie(token);

        //Get refresh toke and create a cookie for it
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
        ResponseCookie jwtRefreshCookie = tokenProviderUtil.generateRefreshJwtCookie(refreshToken.getToken());

        // Build a JSON body for response
        Map<String, String> body = new HashMap<>();
        body.put("token",token);
        body.put("refreshToken",refreshToken.getToken());
        body.put("userName", user.getUsername());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
                .body(body);
    }

    /**
     * Submitted User info to create a regular User
     * @param user
     * @return
     */
    @PostMapping("/signup")
    public String newUser(@RequestBody User user) {
        Set<Role> addRoles = new HashSet<>();
        Role role = new Role(ERole.USER);
        addRoles.add(role);
        user.setRoles(addRoles);
        return userService.createUser(user);
    }

    /**
     * Submitted User info to create an Admin User
     * @param user
     * @return
     */
    @PostMapping("/signup/admin")
    public String newAdmin(@RequestBody User user) {
        Set<Role> addRoles = new HashSet<>();

        Role role = new Role(ERole.USER);
        addRoles.add(role);
        Role roleAdmin = new Role(ERole.ADMIN);
        addRoles.add(roleAdmin);

        user.setRoles(addRoles);
        return userService.createUser(user);
    }
    /**
     * Logout will add JWT to invalid list and delete Refresh tokens
     * */
    @PostMapping("/signout")
    public ResponseEntity<?> logout(@RequestHeader(name="Authorization") String token, HttpServletRequest request) {
        // Gather JWT and User
        String cookiesToken = tokenProviderUtil.getJwtFromCookies(request);
        User user = userAuthService.findByToken(cookiesToken);

        // Adds JWT to invalid list
        userAuthService.logout(cookiesToken);
        // Delete Refresh tokens for the user
        refreshTokenService.deleteByUserId(user.getId());

        // Clears the cookies for the user
        ResponseCookie cookie = tokenProviderUtil.getCleanJwtCookie();
        ResponseCookie refreshCookie = tokenProviderUtil.getCleanJwtRefreshCookie();


        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body("You've been signed out!");
    }
    /** Refresh Token logic
     *
     * */
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refresh(HttpServletRequest request) {

        String refreshToken = tokenProviderUtil.getJwtRefreshFromCookies(request);

        //Check if refreshToken is empty
        if((refreshToken != null) && (refreshToken.length() > 0)){
            //Find token, check if expired, get refresh token user, create JWT and Cookie
            return refreshTokenService.findByToken(refreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        String token = tokenProviderUtil.generateToken(user);
                        ResponseCookie jwtCookie = tokenProviderUtil.generateJwtCookie(token);

                        // Create body for response
                        Map<String, String> body = new HashMap<>();
                        body.put("token",token);
                        body.put("userName", user.getUsername());
                        body.put("message", "Token is refreshed successfully!");

                        //return new JWT Cookie for user
                        return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                .body(body);

                    })
                    // If above fails throw error
                    .orElseThrow(() -> new TokenRefreshException(refreshToken,
                            "Refresh token is not in database!"));
        }
        // Returned for empty cookie
        return ResponseEntity.badRequest().body(new MessageResponse("Refresh Token is empty!"));
    }

}
