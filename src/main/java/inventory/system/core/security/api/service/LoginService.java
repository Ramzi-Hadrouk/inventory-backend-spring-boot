package inventory.system.core.security.api.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import inventory.system.core.security.JwtUtil;
import inventory.system.core.security.SecurityConstants;
import inventory.system.core.security.api.dto.ErrorResponse;
import inventory.system.core.security.api.dto.LoginRequest;
import inventory.system.core.security.api.dto.SuccessAuthResponse;
import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import inventory.system.core.user.Role;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LoginService {
    
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AppUserRepository appUserRepo;

    public ResponseEntity<?> execute(LoginRequest request) {
        try {
            // Load user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.email());
            
            // Verify password manually
            if (!passwordEncoder.matches(request.password(), userDetails.getPassword())) {
                return ResponseEntity.status(401)
                    .body(new ErrorResponse(SecurityConstants.INVALID_CREDENTIALS_MSG));
            }
            
            // Generate JWT token
            String jwt = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());
            
            // Get user info for response
            AppUser appUser = appUserRepo.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
            
            List<String> roles = appUser.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(new SuccessAuthResponse(
                appUser.getEmail(),
                appUser.getFullName(),
                roles,
                jwt
            ));
            
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse(SecurityConstants.INVALID_CREDENTIALS_MSG));
        } catch (Exception e) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse(SecurityConstants.INVALID_CREDENTIALS_MSG));
        }
    }
}