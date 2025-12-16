package spring.security.users.authentication.authorities.auth.users.domain.vo;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInfomation {
    private Long id;
    private String username;
    private String password;
    private int age;
    private String roles;

    public UserInfomation() {
    }

    public UserInfomation(Long id, String username, String password, int age, String roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.age = age;
        this.roles = roles;
    }
}
