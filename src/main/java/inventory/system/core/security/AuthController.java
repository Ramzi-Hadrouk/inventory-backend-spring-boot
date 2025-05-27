package inventory.system.core.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping; // Added for GET mapping
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// DTO imports
import inventory.system.core.security.dto.ErrorResponse;
import inventory.system.core.security.dto.LoginRequest;
import inventory.system.core.security.dto.RegisterRequest;
import inventory.system.core.security.dto.SuccessAuthResponse;
import inventory.system.core.security.dto.UserInfoResponse; // New DTO import

import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService; // This is your CustomUserDetailsService
    private final JwtUtil jwtUtil;
    private final AppUserRepository appUserRepo;
    private final PasswordEncoder passwordEncoder;

    /*--------------Register--------------------------------------------------------------------*/
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            if (appUserRepo.findByEmail(request.getEmail()).isPresent()) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse(SecurityConstants.EMAIL_ALREADY_EXISTS_MSG));
            }

            // Create and save the user
            AppUser appUser = AppUser.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .fullName(request.getFullname())
                    .role(AppUser.Role.USER)
                    .build();
            appUserRepo.save(appUser);

            // Generate token for the newly registered user
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            String token = jwtUtil.generateToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities());

            // Return unified response
            List<String> roles = List.of(appUser.getRole().name()); // Single role as list
            return ResponseEntity.ok(new SuccessAuthResponse(
                    appUser.getEmail(),
                    appUser.getFullName(),
                    roles,
                    token));

        } catch (Exception e) {
            log.error("Registration failed for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse(SecurityConstants.REGISTRATION_FAILED_MSG));
        }
    }

    /*---------------LOGIN----------------------------------------------------------------------*/
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            // Authenticate user
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword());
            authManager.authenticate(authentication);

            // Generate token
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            String token = jwtUtil.generateToken(
                    userDetails.getUsername(),
                    userDetails.getAuthorities());

            // Fetch additional user details (e.g., fullName)
            AppUser appUser = appUserRepo.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Return unified response
            // Return unified response
            List<String> roles = List.of(appUser.getRole().name()); // Single role as list
            return ResponseEntity.ok(new SuccessAuthResponse(
                    appUser.getEmail(),
                    appUser.getFullName(),
                    roles,
                    token));

        } catch (AuthenticationException e) {
            log.warn("Login failed for email {}: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(SecurityConstants.INVALID_CREDENTIALS_MSG));
        }
    }

    /*---------------LOGOUT---------------------------------------------------------------------*/
    @PostMapping("/logout")
    public ResponseEntity<ErrorResponse> logout() {
        return ResponseEntity.ok(new ErrorResponse(SecurityConstants.LOGOUT_SUCCESS_MSG));
    }

    /*---------------GET USER INFO--------------------------------------------------------------*/
    /**
     * Endpoint to retrieve information about the currently authenticated user.
     * The user must provide a valid JWT token in the Authorization header.
     * 
     * @return UserInfoResponse containing email, fullName, and roles, or an error
     *         if not authenticated.
     */
    @GetMapping("/me") // Or any other path you prefer, e.g., "/userinfo"
    public ResponseEntity<?> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("User not authenticated."));
        }

        Object principal = authentication.getPrincipal();
        String email;

        if (principal instanceof UserDetails) {
            email = ((UserDetails) principal).getUsername();
        } else {
            email = principal.toString(); // Fallback, though with JWT UserDetails is expected
        }

        // Fetch AppUser to get the full name, as UserDetails might not have it directly
        // depending on its implementation. Your CustomUserDetailsService loads AppUser.
        AppUser appUser = appUserRepo.findByEmail(email)
                .orElse(null);

        if (appUser == null) {
            // This case should ideally not happen if the token was valid and user exists
            log.error("Authenticated user {} not found in repository.", email);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Could not retrieve user details."));
        }

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        UserInfoResponse userInfo = new UserInfoResponse(
                appUser.getEmail(),
                appUser.getFullName(), // Assuming AppUser has getFullName()
                roles);

        return ResponseEntity.ok(userInfo);
    }
}