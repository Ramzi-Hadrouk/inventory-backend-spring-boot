package inventory.system.core.security.api.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import inventory.system.core.security.JwtUtil;
import inventory.system.core.security.SecurityConstants;
import inventory.system.core.security.api.dto.ErrorResponse;
import inventory.system.core.security.api.dto.RegisterRequest;
import inventory.system.core.security.api.dto.SuccessAuthResponse;
import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import inventory.system.core.user.Role;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RegisterService {

    private final AppUserRepository appUserRepo;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    public ResponseEntity<?> execute(RegisterRequest request) {
        try {
            if (appUserRepo.findByEmail(request.getEmail()).isPresent()) {
                return ResponseEntity.badRequest()
                    .body(new ErrorResponse(SecurityConstants.EMAIL_ALREADY_EXISTS_MSG));
            }

            AppUser appUser = new AppUser(
                null,
                request.getFullname(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                List.of(Role.USER),
                null
            );
            appUserRepo.save(appUser);

            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            String token = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());

            List<String> roles = appUser.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toList());

            return ResponseEntity.ok(new SuccessAuthResponse(
                appUser.getEmail(),
                appUser.getFullName(),
                roles,
                token
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(new ErrorResponse(SecurityConstants.REGISTRATION_FAILED_MSG));
        }
    }
}