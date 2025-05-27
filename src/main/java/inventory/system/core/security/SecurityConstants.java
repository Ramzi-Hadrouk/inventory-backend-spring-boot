package inventory.system.core.security;

public final class SecurityConstants {

    private SecurityConstants() {
        // Prevent instantiation
    }

    // JWT Related Constants
    public static final String JWT_SECRET_KEY = System.getenv("JWT_SECRET_KEY"); // Get from environment
    public static final long JWT_EXPIRATION_MS = 24 * 60 * 60 * 1000; // 24 hours

    public static final String JWT_ROLES_CLAIM = "roles";
    public static final String JWT_AUTHORIZATION_HEADER = "Authorization";
    public static final String JWT_BEARER_PREFIX = "Bearer ";

    // Auth Controller Messages
    public static final String EMAIL_ALREADY_EXISTS_MSG = "Email already exists";
    public static final String USER_REGISTERED_SUCCESS_MSG = "User registered successfully";
    public static final String REGISTRATION_FAILED_MSG = "Registration failed. Please try again later.";
    public static final String INVALID_CREDENTIALS_MSG = "Invalid credentials";
    public static final String LOGOUT_SUCCESS_MSG = "Logged out successfully (token invalidated client-side).";

    }