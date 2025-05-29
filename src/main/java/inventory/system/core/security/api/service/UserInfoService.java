package inventory.system.core.security.api.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import inventory.system.core.security.api.dto.ErrorResponse;
import inventory.system.core.security.api.dto.UserInfoResponse;
import inventory.system.core.user.AppUser;
import inventory.system.core.user.AppUserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserInfoService {

    private final AppUserRepository appUserRepo;

    public ResponseEntity<?> execute() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated() || 
            "anonymousUser".equals(authentication.getPrincipal())) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse("User not authenticated."));
        }

        String email = authentication.getName();
        AppUser appUser = appUserRepo.findByEmail(email).orElse(null);

        if (appUser == null) {
            return ResponseEntity.status(500)
                .body(new ErrorResponse("Could not retrieve user details."));
        }

        List<String> roles = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

        return ResponseEntity.ok(new UserInfoResponse(
            appUser.getEmail(),
            appUser.getFullName(),
            roles
        ));
    }
}