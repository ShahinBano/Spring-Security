package in.sb.spring.security;

import in.sb.spring.security.config.RSAKeyRecord;
import in.sb.spring.security.config.userConfig.UserInfoManageConfig;
import in.sb.spring.security.entity.UserInfoEntity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord.class)
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	public UserInfoEntity userInfoEntity(){
		return new UserInfoEntity();
	}

	@Bean
	public UserInfoManageConfig userInfoManageConfig(){
		return new UserInfoManageConfig();
	}


}
