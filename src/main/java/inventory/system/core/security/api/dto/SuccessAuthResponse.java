package inventory.system.core.security.api.dto;

import java.util.List;

public record SuccessAuthResponse(
    String email,
    String fullName,
    List<String> roles,
    String jwt
) {}
