package com.jwctech.jwtdemo.security.jwt;

import com.jwctech.jwtdemo.security.models.InvalidToken;
import com.jwctech.jwtdemo.security.models.User;
import com.jwctech.jwtdemo.security.repository.InvalidTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;


@Component
public class TokenProviderUtil {

    private static final Logger LOG = LoggerFactory.getLogger(TokenProviderUtil.class);

    @Value("${jwc.app.jwtExpirationSeconds}")
    private Long jwtExpirationSeconds;

    @Value("${jwc.app.jwtCookieName}")
    private String jwtCookie;

    @Value("${jwc.app.jwtRefreshCookieName}")
    private String jwtRefreshCookie;

    private final JwtEncoder encoder;

    private final JwtDecoder decoder;

    private final InvalidTokenRepository invalidTokenRepo;

    public TokenProviderUtil(JwtEncoder encoder, JwtDecoder decoder, InvalidTokenRepository invalidTokenRepo) {
        this.encoder = encoder;
        this.decoder = decoder;
        this.invalidTokenRepo = invalidTokenRepo;
    }

    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public ResponseCookie generateJwtCookie(String token) {
        return ResponseCookie.from(jwtCookie, token).path("/").maxAge(jwtExpirationSeconds).path("/api").httpOnly(true).build();
    }

    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookie, null).path("/api").build();
    }

//    Refresh Token Cookie
    public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
        return generateCookie(jwtRefreshCookie, refreshToken, "/api/auth/refreshtoken");
    }

    public String getJwtRefreshFromCookies(HttpServletRequest request) {
        return getCookieValueByName(request, jwtRefreshCookie);
    }
    public ResponseCookie getCleanJwtRefreshCookie() {
        ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookie, null).path("/api/auth/refreshtoken").build();
        return cookie;
    }

    public String generateToken(User user) {
        Instant now = Instant.now();

        String scope = user.getRoles().stream()
                .map(item -> item.getName().toString())
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(jwtExpirationSeconds, ChronoUnit.SECONDS))
                .subject(user.getUsername())
                .claim("scope", scope)
                .build();

        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // Returns username from token
    public String getUserNameFromJwtToken(String token) {
        return decoder.decode(token).getSubject();
    }

    // Ture is invalid token, False is valid token
    public boolean invalidTokenCheck(String token) {
        InvalidToken foundToken = invalidTokenRepo.findByRevokedToken(token);
        if(foundToken != null) {
            return true;
        }
        return false;
    }

    public void revokeToken(String token) {
        InvalidToken invalidToken= new InvalidToken();
        invalidToken.setRevokedToken(token);
        invalidTokenRepo.save(invalidToken);
        LOG.warn("Invalidating Token!");
    }


    private ResponseCookie generateCookie(String name, String value, String path) {
        return ResponseCookie.from(name, value).path(path).maxAge(24 * 60 * 60).httpOnly(true).build();
    }

    private String getCookieValueByName(HttpServletRequest request, String name) {
        LOG.info(request.getCookies().toString());
        Cookie cookie = WebUtils.getCookie(request, name);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

}
