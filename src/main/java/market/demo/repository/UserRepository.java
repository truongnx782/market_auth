package market.demo.repository;

import market.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User>  findByUsername(String username);

    Optional<User> findByUsernameAndStatus(String username, Integer active);

}
