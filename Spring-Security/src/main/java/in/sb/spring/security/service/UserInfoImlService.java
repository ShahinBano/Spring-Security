package in.sb.spring.security.service;

import in.sb.spring.security.entity.UserInfoEntity;
import in.sb.spring.security.repository.UserInfoEntityRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserInfoImlService implements UserInfoService {

    private final UserInfoEntityRepo userInfoEntityRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserInfoImlService(UserInfoEntityRepo userInfoEntityRepo, PasswordEncoder passwordEncoder) {
        this.userInfoEntityRepo = userInfoEntityRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserInfoEntity createUser(UserInfoEntity userInfoEntity) {
        userInfoEntity.setPassword(passwordEncoder.encode(userInfoEntity.getPassword()));
        return userInfoEntityRepo.save(userInfoEntity);
    }
}
