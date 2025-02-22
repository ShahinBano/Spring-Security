package in.sb.spring.security.config.jwtConfig;

import in.sb.spring.security.config.RSAKeyRecord;
import in.sb.spring.security.constants.GlobalConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@Configuration
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private  final static Logger LOGGER = LoggerFactory.getLogger(JwtAccessTokenFilter.class);

    private final JwtTokenUtils jwtTokenUtils;
    private final RSAKeyRecord rsaKeyRecord;

    @Autowired
    public JwtAccessTokenFilter(JwtTokenUtils jwtTokenUtils, RSAKeyRecord rsaKeyRecord) {
        this.jwtTokenUtils = jwtTokenUtils;
        this.rsaKeyRecord = rsaKeyRecord;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: Startes");
            LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: Filtering HTTP request URI: {}", request.getRequestURI());

            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: Authorization Header: {}", authHeader);

            if (authHeader==null || !authHeader.startsWith(GlobalConstants.TOKEN_TYPE)){
                filterChain.doFilter(request,response);
                LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: Token type not matched: {}", GlobalConstants.TOKEN_TYPE);
                throw new RuntimeException("Invalid Token Type");
            }

            final String accessToken = authHeader.substring(7);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(accessToken);

            final String userName = jwtTokenUtils.getUserName(jwtToken);
            LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: User Name: {}", userName);

            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails = jwtTokenUtils.getUserDetails(userName);
                if(jwtTokenUtils.isTokenValid(jwtToken, userDetails)){
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            LOGGER.info("[JwtAccessTokenFilter : doFilterInternal] :: completed");
            filterChain.doFilter(request,response);

        }catch (JwtValidationException jwtValidationException)
        {
            LOGGER.error("[JwtAccessTokenFilter : doFilterInternal] :: Exception due to {}", jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
        }

    }
}
