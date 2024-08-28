package market.demo.configuration;

import market.demo.entity.Role;
import market.demo.entity.User;
import market.demo.repository.RoleRepository;
import market.demo.repository.UserRepository;
import market.demo.util.ERole;
import market.demo.util.Utils;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationInitConfig {

    private final PasswordEncoder passwordEncoder;

    static final String ADMIN_USER_NAME = "admin";

    static final String ADMIN_PASSWORD = "admin";

    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository,
                                        RoleRepository roleRepository) {
        log.info("Initializing application.....");
        return args -> {

            if (userRepository.findByUsername(ADMIN_USER_NAME).isEmpty()) {

                if (roleRepository.findByName(ERole.ROLE_ADMIN).isEmpty()){
                    Role role = new  Role();
                    role.setName(ERole.ROLE_ADMIN);
                    roleRepository.save(role);
                    log.warn("ADMIN Role has been created!");
                }
                if (roleRepository.findByName(ERole.ROLE_USER).isEmpty()){
                    Role role = new  Role();
                    role.setName(ERole.ROLE_USER);
                    roleRepository.save(role);
                    log.warn("ADMIN Role has been created!");
                }

                Optional<Role> role = roleRepository.findByName(ERole.ROLE_ADMIN);
                User user = User.builder()
                        .username(ADMIN_USER_NAME)
                        .password(passwordEncoder.encode(ADMIN_PASSWORD))
                        .status(Utils.ACTIVE)
                        .roleId(role.get().getId())
                        .build();
                userRepository.save(user);

                log.warn("admin user has been created with default password: admin, please change it");
            }

            log.info("Application initialization completed ....."); // Ghi log thông báo khởi tạo ứng dụng hoàn tất
        };
    }
}
