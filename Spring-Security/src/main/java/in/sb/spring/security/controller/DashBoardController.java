package in.sb.spring.security.controller;

import org.apache.tomcat.util.http.parser.Authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DashBoardController
{
    @GetMapping("/admin-message")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER','ROLE_USER')")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Authentication authentication)
    {
        return ResponseEntity.ok("message : "+ message + authentication.getName());
    }
}
