package in.sb.spring.security.service;

import in.sb.spring.security.config.jwtConfig.JwtGenerateToken;
import in.sb.spring.security.dto.AuthResponseDto;
import in.sb.spring.security.entity.UserInfoEntity;
import in.sb.spring.security.repository.UserInfoEntityRepo;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;


@Service
public class AuthService {

    private final static Logger LOGGER= (Logger) LoggerFactory.getLogger(AuthService.class);

    private final UserInfoEntityRepo userInfoEntityRepo;
    private final JwtGenerateToken jwtGenerateToken;

    @Autowired
    public AuthService(UserInfoEntityRepo userInfoEntityRepo, JwtGenerateToken jwtGenerateToken) {
        this.userInfoEntityRepo = userInfoEntityRepo;
        this.jwtGenerateToken = jwtGenerateToken;
    }

    public AuthResponseDto ceateTokenAfterAuthentication(Authentication authentication, HttpServletResponse httpServletResponse) {

        UserInfoEntity userInfoEntity = userInfoEntityRepo
                .findByEmail(authentication.getName())
                .orElseThrow(()->{
                    LOGGER.info("[AuthService:ceateTokenAfterAuthentication] User not found: {}" + authentication.getName());
                    return  new ResponseStatusException(HttpStatus.NOT_FOUND, "User : " + authentication.getName()+ "does not exist");
                });

        String accessToken = jwtGenerateToken.jwtGenerateAccessToken(authentication);

        return new AuthResponseDto(accessToken, 15*60, "Bearer ", authentication.getName());
    }


}
