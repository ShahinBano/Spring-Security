//package in.sb.spring.security.config.userConfig;
//
//import in.sb.spring.security.entity.UserInfoEntity;
//import in.sb.spring.security.repository.UserInfoEntityRepo;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.List;
//
//@Component
//public class InitialUserInfo implements CommandLineRunner
//{
//    private  final PasswordEncoder passwordEncoder;
//    private final UserInfoEntityRepo userInfoEntityRepo;
//
//    @Autowired
//    public InitialUserInfo(PasswordEncoder passwordEncoder, UserInfoEntityRepo userInfoEntityRepo) {
//        this.passwordEncoder = passwordEncoder;
//        this.userInfoEntityRepo = userInfoEntityRepo;
//    }
//
//    @Override
//    public void run(String... args) throws Exception {
//
//        UserInfoEntity admin= new UserInfoEntity();
//
//        admin.setName("Subhash");
//        admin.setEamil("jeitss2011@gmail.com");
//        admin.setPassword(passwordEncoder.encode("password#123"));
//        admin.setMobileNumber("9439324567");
//        admin.setRoles("ROLE_ADMIN");
//
//        UserInfoEntity manager= new UserInfoEntity();
//
//        manager.setName("Shahin");
//        manager.setEamil("shahin@gmail.com");
//        manager.setPassword(passwordEncoder.encode("password#123"));
//        manager.setMobileNumber("9498324567");
//        manager.setRoles("ROLE_MANAGER");
//
//        UserInfoEntity user= new UserInfoEntity();
//
//        user.setName("rahul");
//        user.setEamil("rahul@gmail.com");
//        user.setPassword(passwordEncoder.encode("password#123"));
//        user.setMobileNumber("9439324567");
//        user.setRoles("ROLE_USER");
//
//        userInfoEntityRepo.saveAll(List.of(admin,manager,user));
//    }
//}
