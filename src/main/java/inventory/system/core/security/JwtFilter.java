package inventory.system.core.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
                                        @NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        @NonNull FilterChain filterChain
                                    ) throws ServletException, IOException {

        String token = extractTokenFromRequest(request);

        if (shouldAuthenticate(token)) {
            String email = jwtUtil.extractEmail(token);
            UserDetails user = userDetailsService.loadUserByUsername(email);

            if (jwtUtil.isTokenValid(token, user.getUsername())) {
                setSecurityContext(user, request);
            }
        }

        filterChain.doFilter(request, response);
    }
    //------------------------------------

    
    // Extracts JWT from Authorization header
    private String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    // Checks whether the request should be authenticated
    private boolean shouldAuthenticate(String token) {
        if (token == null) return false;

        String email = jwtUtil.extractEmail(token);
        boolean notAlreadyAuthenticated = SecurityContextHolder.getContext().getAuthentication() == null;

        return email != null && notAlreadyAuthenticated;
    }

    // Sets the authenticated user into the SecurityContext
    private void setSecurityContext(UserDetails user, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}

