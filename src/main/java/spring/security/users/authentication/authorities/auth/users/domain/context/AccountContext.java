package spring.security.users.authentication.authorities.auth.users.domain.context;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import spring.security.users.authentication.authorities.auth.users.domain.vo.UserInfomation;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class AccountContext implements UserDetails {

    private final UserInfomation userInfomation;
    private final List<GrantedAuthority> grantedAuthorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return userInfomation.getPassword();
    }

    @Override
    public String getUsername() {
        return userInfomation.getUsername();
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
