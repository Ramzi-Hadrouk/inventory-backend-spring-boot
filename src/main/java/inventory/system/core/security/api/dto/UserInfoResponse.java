package inventory.system.core.security.api.dto;

import java.util.List;

public record UserInfoResponse(
    String email,
    String fullName,
    List<String> roles
) {}
