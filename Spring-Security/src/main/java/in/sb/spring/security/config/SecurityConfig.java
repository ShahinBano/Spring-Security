package in.sb.spring.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import in.sb.spring.security.config.userConfig.UserInfoManageConfig;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig
{

    private  final UserInfoManageConfig userInfoManageConfig;
    private final RSAKeyRecord rsaKeyRecord;

    @Autowired
    public SecurityConfig(UserInfoManageConfig userInfoManageConfig, RSAKeyRecord rsaKeyRecord) {
        this.userInfoManageConfig = userInfoManageConfig;
        this.rsaKeyRecord = rsaKeyRecord;
    }


    @Order(1)
    @Bean
    public SecurityFilterChain apiSecurity(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.securityMatcher(new AntPathRequestMatcher("/api/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                //.userDetailsService(userInfoManageConfig)
                .oauth2ResourceServer(oauth2->oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex->{
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Order(1)
    @Bean
    public SecurityFilterChain signInSecurity(HttpSecurity httpSecurity) throws  Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/sign-in/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                .userDetailsService(userInfoManageConfig)
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex->
                {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,authException.getMessage()));
                })
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {return new BCryptPasswordEncoder();}

    @Bean
    public JwtEncoder jwtEncoder(){
        JWK jwt = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey())
                .privateKey(rsaKeyRecord.rsaPrivateKey())
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwt));

        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder
                .withPublicKey(
                        rsaKeyRecord.rsaPublicKey()
                )
                .build();
    }

}
