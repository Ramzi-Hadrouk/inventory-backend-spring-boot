package inventory.system.core.security.api.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SuccessAuthResponse {
    private String email;
    private String fullName;
    private List<String> roles; // List of role strings
    private String token;
}