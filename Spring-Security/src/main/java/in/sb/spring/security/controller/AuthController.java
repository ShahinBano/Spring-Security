package in.sb.spring.security.controller;

import in.sb.spring.security.dto.AuthResponseDto;
import in.sb.spring.security.entity.UserInfoEntity;
import in.sb.spring.security.service.AuthService;
import in.sb.spring.security.service.UserInfoService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController
{
    @Autowired
    private  UserInfoService userInfoService;
    @Autowired
    private  AuthService authService;

//    @Autowired
//    public AuthController(UserInfoService userInfoService, AuthService authService) {
//        this.userInfoService = userInfoService;
//        this.authService = authService;
//    }

    @PostMapping("/sign-up")
    public ResponseEntity<UserInfoEntity> registerUser(@RequestBody UserInfoEntity userInfoEntity)
    {
        return  ResponseEntity.ok(userInfoService.createUser(userInfoEntity));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<AuthResponseDto> userSign(Authentication authentication, HttpServletResponse httpServletResponse){
        return ResponseEntity.ok(authService.ceateTokenAfterAuthentication(authentication, httpServletResponse));
    }
}
