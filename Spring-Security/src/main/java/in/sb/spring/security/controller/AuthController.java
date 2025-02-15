package in.sb.spring.security.controller;

import in.sb.spring.security.entity.UserInfoEntity;
import in.sb.spring.security.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController
{
    private final UserInfoService userInfoService;

    @Autowired
    public AuthController(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<UserInfoEntity> registerUser(@RequestBody UserInfoEntity userInfoEntity)
    {
        return  ResponseEntity.ok(userInfoService.createUser(userInfoEntity));
    }
}
