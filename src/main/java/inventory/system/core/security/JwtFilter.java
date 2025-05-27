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

        if (StringUtils.hasText(token)) { // Check if token is not null and not empty
            try {
                String email = jwtUtil.extractEmail(token);

                // Only authenticate if email is present and there's no existing authentication in context
                if (StringUtils.hasText(email) && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);

                    if (jwtUtil.isTokenValid(token, userDetails.getUsername())) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // Credentials
                                userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        log.debug("User '{}' authenticated successfully.", email);
                    } else {
                        log.warn("Invalid JWT token for user '{}'.", email);
                    }
                }
            } catch (Exception e) {
                // Log an exception if token parsing or validation fails
                log.error("Cannot set user authentication: {}", e.getMessage(), e);
                // Optionally, you could set an error attribute on the request or directly write to response
                // For example, response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); return;
                // However, generally, let Spring Security's ExceptionTranslationFilter handle it later if unauthenticated
            }
        } else {
            log.trace("JWT Token does not begin with Bearer String or is not present.");
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