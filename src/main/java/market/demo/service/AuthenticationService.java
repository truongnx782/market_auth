package market.demo.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Jwt;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import market.demo.dto.request.AuthenticationRequest;
import market.demo.dto.request.IntrospectRequest;
import market.demo.dto.request.RegisterRequest;
import market.demo.dto.request.RootRequest;
import market.demo.dto.response.AuthenticationResponse;
import market.demo.dto.response.IntrospectResponse;
import market.demo.entity.InvalidatedToken;
import market.demo.entity.Role;
import market.demo.entity.User;
import market.demo.exception.AppException;
import market.demo.exception.ErrorCode;
import market.demo.repository.InvalidatedTokenRepository;
import market.demo.repository.RoleRepository;
import market.demo.repository.UserRepository;
import market.demo.repository.httpclient.Market_notificationClient;
import market.demo.util.ERole;
import market.demo.util.Utils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final UserRepository userRepository;
    private final InvalidatedTokenRepository invalidatedTokenRepository;
    private final RoleRepository roleRepository;
    private final JavaMailSender javaMailSender;
    private final Market_notificationClient market_notificationClient;
    private final Map<String, String> otpCache = new ConcurrentHashMap<>();
    private final KafkaTemplate<String, Object> kafkaTemplate;


    @Value("${jwt.signerKey}")
    private String SIGNER_KEY;

    @Value("${jwt.valid-duration}")
    private long VALID_DURATION;

    @Value("${jwt.refreshable-duration}")
    private long REFRESHABLE_DURATION;

    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        var token = request.getToken();
        boolean isValid = true;

        try {
            verifyToken(token, false);
        } catch (Exception e) {
            isValid = false;
        }

        return IntrospectResponse.builder().valid(isValid).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var taiKhoan = userRepository.findByUsernameAndStatus(request.getUsername(), Utils.ACTIVE).orElseThrow(() -> new AppException(ErrorCode.ACCOUNT_NOT_EXISTED));

        Optional<Role> role = roleRepository.findById(taiKhoan.getRoleId());

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

        boolean authenticated = passwordEncoder.matches(request.getPassword(), taiKhoan.getPassword());

        if (!authenticated) throw new AppException(ErrorCode.UNAUTHENTICATED);

        var token = generateToken(taiKhoan, role.get());

        return AuthenticationResponse.builder().token(token).uid(taiKhoan.getId()).build();
    }

    public void logout(String request) throws ParseException, JOSEException {
        try {
            var signToken = verifyToken(request, true);

            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        } catch (AppException exception) {
            log.info("Token already expired");
        }
    }


    private String generateToken(User user, Role role) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        ERole roles = role.getName();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer(user.getPassword())
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", roles)
                .claim("userId",user.getId()) // Thêm userId vào đây
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }
    }


    private SignedJWT verifyToken(String token, boolean isRefresh) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expiryTime = (isRefresh)
                ? new Date(signedJWT
                .getJWTClaimsSet()
                .getIssueTime()
                .toInstant()
                .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS)
                .toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);

        if (!(verified && expiryTime.after(new Date()))) throw new AppException(ErrorCode.UNAUTHENTICATED);

        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        return signedJWT;
    }

    public AuthenticationRequest handleGoogleLogin(Map<String, Object> payload) {
        RootRequest root = new RootRequest();
        root.setEmail((String) payload.get("email"));
        root.setName((String) payload.get("name"));
        root.setSub((String) payload.get("sub"));
        root.setPicture((String) payload.get("picture"));

        Optional<User> user = userRepository.findByUsername(root.getEmail());
        if (user.isEmpty()) {
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
            Optional<Role> role = roleRepository.findByName(ERole.ROLE_USER);

            User u = new User();
            u.setUsername(root.getEmail());
            u.setPassword(passwordEncoder.encode(root.getSub()));
            u.setStatus(Utils.ACTIVE);
            u.setRoleId(role.get().getId());
            userRepository.save(u);

        }
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.setUsername(root.getEmail());
        authenticationRequest.setPassword(root.getSub());
        return authenticationRequest;

    }

    public void register(RegisterRequest request) throws MessagingException {
        Optional<User> user = userRepository.findByUsername(request.getEmail());
        if (user.isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        } else {
            Random random = new Random();
            int randomNumber = random.nextInt(9000) + 1000;
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("email", request.getEmail());
            objectMap.put("password", passwordEncoder.encode(request.getPassword()));
            objectMap.put("randomNumber", randomNumber);

            try {
//                market_notificationClient.sendMailRegister(objectMap);
                kafkaTemplate.send("mail-register-topic", objectMap);
                otpCache.put(request.getEmail(), String.valueOf(randomNumber));
            } catch (Exception e) {
                throw new RuntimeException("Failed to send OTP email", e);
            }

        }
    }

    public void confirmRegister(String email, String password, String otp) {
        System.out.println(email);
        System.out.println(password);
        System.out.println(otp);
        String storedOtp = otpCache.get(email);
        if (storedOtp == null || !storedOtp.equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP");
        }

        Optional<User> user = userRepository.findByUsername(email);
        if (user.isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }
        User u = new User();

        Optional<Role> role = roleRepository.findByName(ERole.ROLE_USER);

        u.setUsername(email);
        u.setStatus(Utils.ACTIVE);
        u.setPassword(password);
        u.setRoleId(role.get().getId());
        userRepository.save(u);
    }


    public void forgotPassword(Map<String, Object> payload) throws MessagingException {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        Random random = new Random();
        int randomNumber = random.nextInt(9000) + 1000;

        String email = (String) payload.get("email");
        String password = (String) payload.get("password");

        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email is empty or null");
        }

        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password is empty or null");
        }

        Optional<User> user = userRepository.findByUsername(email);
        if (user.isEmpty()) {
            throw new IllegalArgumentException("Email not found");
        }


        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("email", email);
        objectMap.put("password", passwordEncoder.encode(password));
        objectMap.put("randomNumber", randomNumber);

        try {
//            market_notificationClient.sendMailForgotPassword(objectMap);
            kafkaTemplate.send("mail-forgot-password-topic", objectMap);

            otpCache.put(email, String.valueOf(randomNumber));
        } catch (Exception e) {
            throw new RuntimeException("Failed to send OTP email", e);
        }
    }

    public void confirmForgotPassword(String email, String password, String otp) {
        String storedOtp = otpCache.get(email);
        if (storedOtp == null || !storedOtp.equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP");
        }
        Optional<User> user = userRepository.findByUsername(email);
        if (user.isEmpty()) {
            throw new IllegalArgumentException("Email not found");
        }

        User foundUser = user.get();
        foundUser.setPassword(password);
        userRepository.save(foundUser);
        otpCache.remove(email);
    }


    public Map<String, Object> validateToken(String token) throws ParseException, JOSEException {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Invalid token");
        }
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        // Verify and parse the token
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        if (!signedJWT.verify(verifier)) {
            throw new AppException(ErrorCode.UNAUTHORIZED);
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();

        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            throw new AppException(ErrorCode.ACCOUNT_NOT_EXISTED);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("uid", userOptional.get().getId());
        return response;
    }


    public AuthenticationResponse refreshToken(String token) throws ParseException, JOSEException {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Invalid token");
        }

        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        SignedJWT signedJWT = SignedJWT.parse(token);

        // Verify the token and check its expiration
        verifyToken(token, true);

        // Generate a new token
        User user = userRepository.findByUsername(signedJWT.getJWTClaimsSet().getSubject())
                .orElseThrow(() -> new AppException(ErrorCode.ACCOUNT_NOT_EXISTED));

        Optional<Role> role = roleRepository.findById(user.getRoleId());


        // Generate a new token with updated expiration
        String newToken = generateToken(user, role.get());

        return AuthenticationResponse.builder()
                .token(newToken)
                .build();
    }

    @Scheduled(fixedDelay = 180000)
    public void autoDeleteUser() {
        otpCache.clear();
    }

}
