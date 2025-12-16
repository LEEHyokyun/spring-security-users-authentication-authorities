package spring.security.users.authentication.authorities.auth.config.provider;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import spring.security.users.authentication.authorities.auth.config.details.FormAuthenticationDetails;
import spring.security.users.authentication.authorities.auth.config.exception.SecretException;
import spring.security.users.authentication.authorities.auth.users.domain.context.AccountContext;

@Component("authenticationProvider")
@RequiredArgsConstructor
public class FormAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        AccountContext accountContext = (AccountContext)  userDetailsService.loadUserByUsername(username);

        //auth 1
        if(!passwordEncoder.matches(password, accountContext.getPassword())){
            throw new BadCredentialsException("Incorrect password");
        }

        //auth 2
        String secretKey = ((FormAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if(secretKey == null || secretKey.equals("") || !secretKey.equals("secret")){
            throw new SecretException("Invalid secret key");
        }

        return new  UsernamePasswordAuthenticationToken(accountContext, null, accountContext.getAuthorities());
    }

    //pro
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
