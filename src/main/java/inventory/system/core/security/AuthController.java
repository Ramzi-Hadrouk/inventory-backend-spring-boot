package inventory.system.core.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import inventory.system.core.security.dto.LoginRequest;
import inventory.system.core.security.dto.LoginResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

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

}