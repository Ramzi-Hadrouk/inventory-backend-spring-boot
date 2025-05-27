package inventory.system.core.security;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import java.security.Key;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private final Key key;
    private final long expirationMs;


    public JwtUtil(@Value("${jwt.secret-key}") String secretString,
                   @Value("${jwt.expiration-ms}") long expirationMs) {
        byte[] keyBytes = Decoders.BASE64.decode(secretString);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }
    

    /**
     * Generates a JWT token for the given email and authorities.
     *
     * @param email       The email of the user.
     * @param authorities The authorities (roles) of the user.
     * @return A JWT token as a String.
     */
    public String generateToken(String email, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(SecurityConstants.JWT_ROLES_CLAIM, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .setSubject(email)
                .addClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extracts the email (subject) from the JWT token.
     *
     * @param token The JWT token.
     * @return The email extracted from the token.
     */
    public String extractEmail(String token) {
        return parseToken(token).getSubject();
    }

    /**
     * Validates the JWT token.
     *
     * @param token The JWT token.
     * @param email The email to compare against the token's subject.
     * @return True if the token is valid, false otherwise.
     */
    public boolean isTokenValid(String token, String email) {
        return extractEmail(token).equals(email) && !isTokenExpired(token);
    }

    /**
     * Checks if the JWT token is expired.
     *
     * @param token The JWT token.
     * @return True if the token is expired, false otherwise.
     */
    private boolean isTokenExpired(String token) {
        return parseToken(token).getExpiration().before(new Date());
    }

    /**
     * Parses the JWT token to extract its claims.
     *
     * @param token The JWT token.
     * @return The claims contained in the token.
     */
    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
