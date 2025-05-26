package inventory.system.core.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginSuccessResponse {
    private String token;
}
