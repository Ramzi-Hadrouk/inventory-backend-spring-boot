package inventory.system.core.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import inventory.system.core.User.AppUser;
import inventory.system.core.User.AppUserRepository;
import inventory.system.core.security.dto.ErrorResponse;
import inventory.system.core.security.dto.LoginRequest;
import inventory.system.core.security.dto.LoginResponse;
import inventory.system.core.security.dto.RegisterRequest;
import inventory.system.core.security.dto.RegisterSuccessResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {


    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final AppUserRepository appUserRepo;
    private final PasswordEncoder passwordEncoder;

    /*---------------LOGIN---*/
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            // 1. Authenticate the user using their username and password
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            );
            authManager.authenticate(authentication);
            // 2. Load the full user details from the database
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            // 3. Generate a JWT token using the user's username and authorities (roles)
            String token = jwtUtil.generateToken(
                userDetails.getUsername(),
                userDetails.getAuthorities()
            );
            // 4. Return the token in a response object
            return ResponseEntity.ok(new LoginResponse(token));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("Invalid credentials"));
        }
    }

    /*---------------LOGOUT--*/
    @PostMapping("/logout")
    public String logout() {
        // JWT-based logout = handled on frontend: just delete token from local storage/cookies
        return "Logged out successfully (just delete the token client-side).";
    }

    /*--------------Register-*/
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            if (appUserRepo.findByEmail(request.getEmail()).isPresent()) {
                return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Email already exists"));
            }

            AppUser appUser = AppUser.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .fullName(request.getFullname())
                    .role(AppUser.Role.USER)
                    .build();

            appUserRepo.save(appUser);
            return ResponseEntity.ok(new RegisterSuccessResponse("User registered successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("Registration failed"));
        }
    }



}