package com.jwctech.jwtdemo.Service;

import com.jwctech.jwtdemo.entity.User;

import java.util.Optional;

public interface UserAuthenticationService {
    /**
     * Logs in with the given {@code username} and {@code password}.
     *
     * @param username
     * @param password
     * @return an {@link Optional} of a user when login succeeds
     */
    String login(String username, String password);

    /**
     * Finds a user by its dao-key.
     *
     * @param token user dao key
     * @return
     */
    User findByToken(String token);

    /**
     * Logs out the given input {@code user}.
     *
     * @param user the user to logout
     */
    void logout(User user);

    /**
     * Refreshes the given input {@code token}.
     *
     * @param token the token to refresh
     */
    String refresh(String token);
}
