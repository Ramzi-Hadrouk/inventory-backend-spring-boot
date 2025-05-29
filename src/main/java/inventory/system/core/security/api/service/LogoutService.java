package inventory.system.core.security.api.service;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import inventory.system.core.security.SecurityConstants;
import inventory.system.core.security.api.dto.ErrorResponse;

@Service
public class LogoutService {
    public ResponseEntity<ErrorResponse> execute() {
        return ResponseEntity.ok(new ErrorResponse(SecurityConstants.LOGOUT_SUCCESS_MSG));
    }
}