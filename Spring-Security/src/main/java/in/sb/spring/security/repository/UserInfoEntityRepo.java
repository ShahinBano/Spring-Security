package in.sb.spring.security.repository;

import in.sb.spring.security.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoEntityRepo extends JpaRepository<UserInfoEntity,Long> {
    Optional<UserInfoEntity> findByEmail(String email);
}
