package in.sb.spring.security.service;

import in.sb.spring.security.entity.UserInfoEntity;
import in.sb.spring.security.repository.UserInfoEntityRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserInfoImlService implements UserInfoService {

    private final UserInfoEntityRepo userInfoEntityRepo;

    @Autowired
    public UserInfoImlService(UserInfoEntityRepo userInfoEntityRepo) {
        this.userInfoEntityRepo = userInfoEntityRepo;
    }

    @Override
    public UserInfoEntity createUser(UserInfoEntity userInfoEntity) {
        return userInfoEntityRepo.save(userInfoEntity);
    }
}
