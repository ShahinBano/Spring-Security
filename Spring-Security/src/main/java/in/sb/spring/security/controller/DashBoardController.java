package in.sb.spring.security.controller;

import org.apache.tomcat.util.http.parser.Authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class DashBoardController
{
    @GetMapping("/admin-message")
    //@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER','ROLE_USER')")
    @PreAuthorize("hasAnyAuthority('SCOPE_READ','SCOPE_WRITE','SCOPE_DELETE','SCOPE_MODIFY')")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Authentication authentication)
    {
        return ResponseEntity.ok("message : "+ message + authentication.getName());
    }

    @GetMapping("/manager-message")
    //@PreAuthorize("hasRole('ROLE_MANAGER')")
    @PreAuthorize("hasAnyAuthority('SCOPE_WRITE','SCOPE_MODIFY')")
    public ResponseEntity<String> getManagerData(@RequestParam("message") String message, Principal principal)
    {
        return ResponseEntity.ok("message : "+ message + principal.getName());
    }

    @GetMapping("/user-message")
    //@PreAuthorize("hasRole('ROLE_USER')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    public ResponseEntity<String> getUserData(@RequestParam("message") String message, Principal principal)
    {
        return ResponseEntity.ok("message : "+ message + principal.getName());
    }
}
