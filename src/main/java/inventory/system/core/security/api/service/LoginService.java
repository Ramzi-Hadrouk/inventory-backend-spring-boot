package inventory.system.core.security.api.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final AppUserRepository appUserRepo;

    public ResponseEntity<?> execute(LoginRequest request) {
        try {
            authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            UserDetails userDetails = userDetailsService.loadUserByUsername(request.email());
            String jwt = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

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
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse(SecurityConstants.INVALID_CREDENTIALS_MSG));
        }
    }
}