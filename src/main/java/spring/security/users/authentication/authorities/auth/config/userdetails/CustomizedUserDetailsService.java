package spring.security.users.authentication.authorities.auth.config.userdetails;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import spring.security.users.authentication.authorities.auth.users.domain.context.AccountContext;
import spring.security.users.authentication.authorities.auth.users.domain.entity.Account;
import spring.security.users.authentication.authorities.auth.users.domain.vo.UserInfomation;
import spring.security.users.authentication.authorities.auth.users.repository.UserRepository;

import java.util.List;

@Service("userDetailsService")
@RequiredArgsConstructor
public class CustomizedUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if(account == null) {
            throw new UsernameNotFoundException(username);
        }

        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRoles()));
        ModelMapper modelMapper = new ModelMapper();
        UserInfomation userInfomation = modelMapper.map(account, UserInfomation.class);

        return new AccountContext(userInfomation, authorities);
    }
}
