package com.jwctech.jwtdemo.Service.impl;

import com.jwctech.jwtdemo.Service.TokenService;
import com.jwctech.jwtdemo.entity.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class TokenServiceImpl implements TokenService {

        private final JwtEncoder encoder;

        private final JwtDecoder decoder;

        public TokenServiceImpl(JwtEncoder encoder, JwtDecoder decoder) {
            this.encoder = encoder;
            this.decoder = decoder;
        }

        public String generateToken(String username, Set<Role> roles) {
            Instant now = Instant.now();
            String scope = roles.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("self")
                    .issuedAt(now)
                    .expiresAt(now.plus(1, ChronoUnit.HOURS))
                    .subject(username)
                    .claim("scope", scope)
                    .build();
            return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        }

        public String parseToken(String token) {
            String username = decoder.decode(token).getSubject();

            return username;
        }

    @Override
    public boolean validateToken(String token) {
        return false;
    }

    @Override
    public String refreshToken(String token) {
        return null;
    }
}
