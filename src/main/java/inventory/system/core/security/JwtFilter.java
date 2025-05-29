package inventory.system.core.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils; // For StringUtils.hasText

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.micrometer.common.lang.NonNull; // Replaced with standard NonNull if preferred


@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService; // This is your CustomUserDetailsService

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String token = extractTokenFromRequest(request);
        log.debug("Processing request to '{}' with token: {}", request.getRequestURI(), 
            token != null ? "present" : "not present");

        if (StringUtils.hasText(token)) {
            try {
                String email = jwtUtil.extractEmail(token);
                log.debug("Extracted email from token: {}", email);

                if (StringUtils.hasText(email) && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
                    log.debug("Loaded user details for {}, authorities: {}", email, 
                        userDetails.getAuthorities());

                    if (jwtUtil.isTokenValid(token, userDetails.getUsername())) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        log.debug("Successfully authenticated user '{}' with authorities: {}", 
                            email, userDetails.getAuthorities());
                    } else {
                        log.warn("Token validation failed for user '{}'", email);
                        SecurityContextHolder.clearContext();
                    }
                }
            } catch (Exception e) {
                log.error("Authentication failed: {}", e.getMessage(), e);
                SecurityContextHolder.clearContext();
            }
        } else {
            log.debug("No JWT token found in request");
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT from the Authorization header.
     * @param request The HTTP request.
     * @return The token string or null if not found.
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(SecurityConstants.JWT_AUTHORIZATION_HEADER); // Use constant
        if (StringUtils.hasText(authHeader) && authHeader.startsWith(SecurityConstants.JWT_BEARER_PREFIX)) { // Use constant
            return authHeader.substring(SecurityConstants.JWT_BEARER_PREFIX.length());
        }
        return null;
    }

    // The shouldAuthenticate logic has been integrated into doFilterInternal for clarity
    // The setSecurityContext logic is also part of doFilterInternal now.
}