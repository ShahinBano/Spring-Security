package in.sb.spring.security.config.jwtConfig;

import in.sb.spring.security.repository.UserInfoEntityRepo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtTokenUtils {

    private final UserInfoEntityRepo userInfoEntityRepo;

    public JwtTokenUtils(UserInfoEntityRepo userInfoEntityRepo) {
        this.userInfoEntityRepo = userInfoEntityRepo;
    }

    public String getUserName(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    public UserDetails getUserDetails(String userName) {
        return userInfoEntityRepo.findByEmail(userName)
                .map(userInfoEntity -> {
                    List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(userInfoEntity.getRoles()));
                    return  new User(userInfoEntity.getEmail(), userInfoEntity.getPassword(), authorities);
                }).orElseThrow(()->new UsernameNotFoundException("User : "+ userName + " does not exists"));
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails) {
       final String userName = getUserName(jwtToken);
       boolean isTokenExpired = getIfTokenExpired(jwtToken);
       boolean isUserSameAsDatabase = userName.equals(userDetails.getUsername());

       return !isTokenExpired && isUserSameAsDatabase;
    }

    private boolean getIfTokenExpired(Jwt jwtToken) {
        return jwtToken.getExpiresAt().isBefore(Instant.now());
    }
}
