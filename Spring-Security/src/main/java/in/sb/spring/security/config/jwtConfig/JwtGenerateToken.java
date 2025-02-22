package in.sb.spring.security.config.jwtConfig;

import com.nimbusds.jwt.JWTClaimsSet;
import in.sb.spring.security.repository.UserInfoEntityRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtGenerateToken
{
    private final static Logger LOGGER= LoggerFactory.getLogger(JwtGenerateToken.class);

    private final UserInfoEntityRepo userInfoEntityRepo;
    private final JwtEncoder jwtEncoder;

    @Autowired
    public JwtGenerateToken(UserInfoEntityRepo userInfoEntityRepo, JwtEncoder jwtEncoder) {
        this.userInfoEntityRepo = userInfoEntityRepo;
        this.jwtEncoder = jwtEncoder;
    }

    public String jwtGenerateAccessToken(Authentication authentication)
    {
        LOGGER.info("[JwtGenerateToken:jwtGenerateAccessToken] Token Generation Started .");

        String roles = getRolesOfUser(authentication);
        LOGGER.info("[JwtGenerateToken:jwtGenerateAccessToken] Roles of User : "+roles);

        Set<String> permissions = getPermissonOfUser(roles);
        LOGGER.info("[JwtGenerateToken:jwtGenerateAccessToken] Permission of User based Roles {} : "+permissions);

        JwtClaimsSet jwtClaims = JwtClaimsSet.builder()
                .issuer("Shahin")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .claim("scope", permissions)
                .subject(authentication.getName())
                .build();

        String tokenValue = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaims)).getTokenValue();

        return tokenValue;
    }

    private Set<String> getPermissonOfUser(String roles) {

        Set<String> permissions= new HashSet<>();
        if(roles.contains("ROLE_ADMIN")){
            permissions.addAll(List.of("READ", "WRITE","DELETE","MODIFY"));
        } else if (roles.contains("ROLE_MANAGER")) {
            permissions.addAll(List.of("WRITE", "MODIFY"));
        }else {
            permissions.add("READ");
        }
        return permissions;
    }

    private String getRolesOfUser(Authentication authentication) {
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }
}
