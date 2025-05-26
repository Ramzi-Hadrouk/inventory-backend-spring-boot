package inventory.system.core.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import inventory.system.core.User.AppUser;
import inventory.system.core.User.AppUserRepository;
import inventory.system.core.security.dto.LoginRequest;
import inventory.system.core.security.dto.LoginResponse;
import inventory.system.core.security.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final AppUserRepository appUserRepo;
    private final PasswordEncoder passwordEncoder;

    /*---------------LOGIN---*/
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
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
    return new LoginResponse(token);
    }

    /*---------------LOGOUT--*/
    @PostMapping("/logout")
    public String logout() {
        // JWT-based logout = handled on frontend: just delete token from local storage/cookies
        return "Logged out successfully (just delete the token client-side).";
    }

    /*--------------Register-*/
    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        if (appUserRepo.findByEmail(request.getEmail()).isPresent()) {
            return "Username already exists.";
        }

        AppUser appUser = AppUser.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullname())
                .role(AppUser.Role.USER)
                .build();

        appUserRepo.save(appUser);
        return "User registered successfully.";
    }



}