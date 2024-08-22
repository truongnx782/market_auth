package market.demo.controller;

import com.nimbusds.jose.JOSEException;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import market.demo.dto.request.AuthenticationRequest;
import market.demo.dto.request.IntrospectRequest;
import market.demo.dto.request.RegisterRequest;
import market.demo.repository.UserRepository;
import market.demo.service.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;


    @PostMapping("/validate-url-token")
    public ResponseEntity<?> validateUrlToken(
            @RequestParam("url") String url,
            @RequestParam("token") String token) {
        boolean isValid = authenticationService.validateUrlToken(url, token);

        if (isValid) {
            return ResponseEntity.ok("URL and token are valid");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid URL or token");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        var result = authenticationService.authenticate(request);
        return ResponseEntity.ok()
                .header("token", result.getToken())
                .body(result);
    }

    //    @PreAuthorize("hasRole('USER')")
    @GetMapping("/getAll")
    public ResponseEntity<?> getAll() {
        var result = userRepository.findAll();
        return ResponseEntity.ok(result);
    }

    @PostMapping("/register")
    public ResponseEntity<?> Register(@Valid @RequestBody RegisterRequest request) throws MessagingException {
        authenticationService.register(request);
        return ResponseEntity.ok(Map.of("message", "SENDING_MAIL_SUCCESSFULLY"));

    }

    @GetMapping("/confirm-register")
    public ResponseEntity<?> confirmRegister(@RequestParam("email") String email,
                                             @RequestParam("password") String password,
                                             @RequestParam("otp") String otp) {
        authenticationService.confirmRegister(email, password, otp);
        return ResponseEntity.ok("Xác thực tài khoản thành công!");
    }

    @PostMapping("/introspect")
    public ResponseEntity<?> authenticate(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        var result = authenticationService.introspect(request);
        return ResponseEntity.ok(result);
    }


    @PostMapping("/logout")
    public void logout(@RequestBody Map<String, Object> objectMap) throws ParseException, JOSEException {
        String request = (String) objectMap.get("token");
        authenticationService.logout(request);
    }

    @PostMapping("/login-google")
    public ResponseEntity<?> handleGoogleLogin(@RequestBody Map<String, Object> payload) {
        var authenticationRequest = authenticationService.handleGoogleLogin(payload);
        var result = authenticationService.authenticate(authenticationRequest);
        return ResponseEntity.ok()
                .header("token", result.getToken())
                .body(result);

    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, Object> payload) throws MessagingException {
        authenticationService.forgotPassword(payload);
        return ResponseEntity.ok(Map.of("message", "SENDING_MAIL_SUCCESSFULLY"));
    }

    @GetMapping("/confirm-forgot-password")
    public ResponseEntity<?> confirmForgotPassword(@RequestParam("email") String email,
                                                   @RequestParam("password") String password,
                                                   @RequestParam("otp") String otp) {
        authenticationService.confirmForgotPassword(email, password, otp);
        return ResponseEntity.ok("Xác thực tài khoản thành công!");
    }

    @PostMapping("/check-token")
    public ResponseEntity<?> validateToken
            (@RequestHeader("Authorization") String token) throws ParseException, JOSEException {
        var result = authenticationService.validateToken(token);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refresh(@RequestHeader("Authorization") String token) {
        try {
            var result = authenticationService.refreshToken(token);
            return ResponseEntity.ok()
                    .header("token", result.getToken())
                    .body("Token refreshed successfully");
        } catch (ParseException | JOSEException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to refresh token");
        }
    }


}
