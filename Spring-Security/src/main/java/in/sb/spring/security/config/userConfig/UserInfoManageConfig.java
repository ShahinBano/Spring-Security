package in.sb.spring.security.config.userConfig;

import in.sb.spring.security.repository.UserInfoEntityRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class UserInfoManageConfig implements UserDetailsService {

    @Autowired
    private UserInfoEntityRepo userInfoEntityRepo;

    public UserInfoManageConfig() {
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userInfoEntityRepo
                .findByEmail(username)
                .map(userInfoEntity -> {
                    List<GrantedAuthority> authorities = Arrays.asList(
                            new SimpleGrantedAuthority(
                                    userInfoEntity.getRoles()));

                    return new User(userInfoEntity.getEmail(),userInfoEntity.getPassword(),authorities);
                }).orElseThrow(()->new UsernameNotFoundException("User Email Id : "+username+" does not exist"));
    }
}
