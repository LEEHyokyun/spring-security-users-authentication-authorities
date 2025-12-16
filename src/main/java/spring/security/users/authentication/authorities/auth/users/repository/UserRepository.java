package spring.security.users.authentication.authorities.auth.users.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import spring.security.users.authentication.authorities.auth.users.domain.entity.Account;

@Repository
public interface UserRepository extends JpaRepository<Account, Long> {

    Account findByUsername(String username);
}
