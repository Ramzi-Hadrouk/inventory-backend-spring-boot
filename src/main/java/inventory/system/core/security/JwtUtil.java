package inventory.system.core.security;


import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import java.security.Key;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
    /*--------CONSTANT------ */
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final long expiration = 1000 * 60 * 60 * 24; // 24 ساعة
  
    /*--------METHODS------ */
  
    /**
     * Generates a JWT token for the given email and authorities.
     *
     * @param email       The email of the user.
     * @param authorities The authorities (roles) of the user.
     * @return A JWT token as a String.
     */
    public String generateToken(String email, Collection<? extends GrantedAuthority> authorities) {
     
        Map<String, Object> claims = new HashMap<>();

        claims.put("roles", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .setSubject(email)
                .addClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }



    public String extractEmail(String token) {
        return parseToken(token).getSubject();
    }

    public boolean isTokenValid(String token, String email) {
        return extractEmail(token).equals(email) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return parseToken(token).getExpiration().before(new Date());
    }

    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
