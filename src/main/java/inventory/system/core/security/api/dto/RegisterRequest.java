package inventory.system.core.security.api.dto;


public record RegisterRequest(
    String email,
    String password,
    String fullname
) {}
