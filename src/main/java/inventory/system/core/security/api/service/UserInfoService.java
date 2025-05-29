package inventory.system.core.security.api.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import inventory.system.core.security.JwtUtil;
import inventory.system.core.security.api.dto.ErrorResponse;
import inventory.system.core.security.api.dto.UserInfoResponse;
import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import lombok.RequiredArgsConstructor;

import io.jsonwebtoken.Claims;

@Service
@RequiredArgsConstructor
public class UserInfoService {

    private final AppUserRepository appUserRepo;
    private final JwtUtil jwtUtil;

    public ResponseEntity<?> execute() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = null;
        List<String> roles = null;
        AppUser appUser = null;

        if (authentication != null && authentication.isAuthenticated() &&
            !"anonymousUser".equals(authentication.getPrincipal())) {
            email = authentication.getName();
            appUser = appUserRepo.findByEmail(email).orElse(null);
            roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        } else {
            // Try to extract from JWT manually
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);
                    try {
                        Claims claims = jwtUtil.getAllClaims(token);
                        email = claims.getSubject();
                        @SuppressWarnings("unchecked")
                        List<String> extractedRoles = (List<String>) claims.get("roles", List.class);
                        roles = extractedRoles;
                        appUser = appUserRepo.findByEmail(email).orElse(null);
                    } catch (Exception e) {
                        return ResponseEntity.status(401)
                            .body(new ErrorResponse("Invalid or expired token."));
                    }
                }
            }
        }

        if (email == null || appUser == null) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse("User not authenticated."));
        }

        if (roles != null) {
            roles = roles.stream()
                .map(r -> r.startsWith("ROLE_") ? r.substring(5) : r)
                .collect(Collectors.toList());
        }

        return ResponseEntity.ok(new UserInfoResponse(
            appUser.getEmail(),
            appUser.getFullName(),
            roles
        ));
    }
}