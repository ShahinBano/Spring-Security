package in.sb.spring.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
/*@Data
@AllArgsConstructor
@NoArgsConstructor*/
@Entity
@Table(name = "user_info")
public class UserInfoEntity {
    @Id
    @GeneratedValue
      private Long id;

    @Column(name = "USER_NAME", nullable = false)
    private String name;

    @Column(name = "EMAI_ID", nullable = false)
    private String email;

    @Column(name = "PASSWORD", nullable = false)
    private String password;

    @Column(name = "MOBILE_NO", nullable = false)
    private String mobileNumber;

    @Column(name = "USER_ROLES", nullable = false)
    private String roles;

    public UserInfoEntity() {
    }

    public UserInfoEntity(Long id, String name, String email, String password, String mobileNumber, String roles) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.mobileNumber = mobileNumber;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEamil(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public void setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "UserInfoEntity{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", mobileNumber='" + mobileNumber + '\'' +
                ", roles='" + roles + '\'' +
                '}';
    }
}
