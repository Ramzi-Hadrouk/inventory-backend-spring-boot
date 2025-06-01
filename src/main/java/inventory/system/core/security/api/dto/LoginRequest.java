package inventory.system.core.security.api.dto;

 
public record LoginRequest(
    String email,
    String password
) {}
