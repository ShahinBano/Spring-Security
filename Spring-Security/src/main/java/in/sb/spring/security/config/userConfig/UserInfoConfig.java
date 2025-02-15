package in.sb.spring.security.config.userConfig;

import in.sb.spring.security.entity.UserInfoEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Component
public class UserInfoConfig implements UserDetails {

    private final UserInfoEntity userInfoEntity;

    public UserInfoConfig(UserInfoEntity userInfoEntity) {
        this.userInfoEntity = userInfoEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays
                .stream(userInfoEntity.getRoles().split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getPassword() {
        return userInfoEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userInfoEntity.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
