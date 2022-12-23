package com.jwctech.jwtdemo.util;

import com.jwctech.jwtdemo.entity.InvalidToken;
import com.jwctech.jwtdemo.entity.Role;
import com.jwctech.jwtdemo.repository.InvalidTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import static java.lang.String.format;

@Service
public class TokenProviderUtil {

    private static final Logger LOG = LoggerFactory.getLogger(TokenProviderUtil.class);

        private final JwtEncoder encoder;

        private final JwtDecoder decoder;

        private final InvalidTokenRepository invalidTokenRepo;

        public TokenProviderUtil(JwtEncoder encoder, JwtDecoder decoder, InvalidTokenRepository invalidTokenRepo) {
            this.encoder = encoder;
            this.decoder = decoder;
            this.invalidTokenRepo = invalidTokenRepo;
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
            String clams = decoder.decode(token).getClaims().toString();
            System.out.println("clams: " + clams);
            String username = decoder.decode(token).getSubject();

            return username;
        }


    public boolean validateToken(String token) {
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

    public String refreshToken(String token) {
        return null;
    }
}
