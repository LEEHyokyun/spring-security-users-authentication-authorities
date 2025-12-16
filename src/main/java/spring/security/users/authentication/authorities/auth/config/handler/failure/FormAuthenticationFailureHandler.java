package spring.security.users.authentication.authorities.auth.config.handler.failure;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;
import spring.security.users.authentication.authorities.auth.config.exception.SecretException;

import java.io.IOException;

@Component
public class FormAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
        String errorMsg = "Invalid Username or Password"; //default msg

        if(authenticationException instanceof BadCredentialsException){
            errorMsg = "Invalid Username or Password";
        }else if(authenticationException instanceof UsernameNotFoundException){
            errorMsg = "User Information Not Found";
        }else if(authenticationException instanceof CredentialsExpiredException){
            errorMsg = "Credentials Expired";
        }else if(authenticationException instanceof SecretException){
            errorMsg = "secretKey is invalid";
        }

        setDefaultFailureUrl("/login?error=true&exception="+ errorMsg);   //login* permitAll
        super.onAuthenticationFailure(request, response, authenticationException);
    }
}
