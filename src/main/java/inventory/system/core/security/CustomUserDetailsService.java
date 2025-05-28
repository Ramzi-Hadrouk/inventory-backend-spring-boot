package inventory.system.core.security;



import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final AppUserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AppUser user = userRepo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // Convert List<String> to String[]
        String[] roles= user.getRoles().stream()
                .map(role -> role.name()) // Or use Role::name
                .toArray(String[]::new); // Convert to String array
        // Ensure AppUser.Role has a .name() method or similar to get the role string
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .roles(roles) // Assuming getRole() returns an enum with a name() method
                // If user.getRole() returns a collection of GrantedAuthority, use
                // .authorities(user.getAuthorities())
                .build();
    }
}