package spring.security.users.authentication.authorities.auth.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import spring.security.users.authentication.authorities.auth.token.FetchAuthenticationToken;
import spring.security.users.authentication.authorities.auth.users.domain.vo.UserInfomation;
import spring.security.users.authentication.authorities.util.WebUtil;

import java.io.IOException;

public class FetchAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper  objectMapper = new ObjectMapper();

    public FetchAuthenticationFilter(HttpSecurity httpSecurity) throws Exception {
        super(new AntPathRequestMatcher("/fetch/login", "POST"));
        setSecurityContextRepository(getSecurityContextRepository(httpSecurity));
    }

    //인증필터 동작 패턴 정의(url/method)
    public FetchAuthenticationFilter() {
        super(new AntPathRequestMatcher("/fetch/login", "POST"));
    }

    public SecurityContextRepository getSecurityContextRepository(HttpSecurity http) {
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        if (securityContextRepository == null) {
            securityContextRepository = new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(),
                    new HttpSessionSecurityContextRepository()
            );
        }

        //session
        return securityContextRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if(!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalArgumentException("Authentication method not supported: " + request.getMethod());
        }

        UserInfomation userInfomation = objectMapper.readValue(request.getReader(), UserInfomation.class);

        if(!StringUtils.hasText(userInfomation.getUsername()) || !StringUtils.hasText(userInfomation.getPassword())) {
            throw new AuthenticationServiceException("Username or password is empty");
        }

        FetchAuthenticationToken fetchAuthenticationToken =  new FetchAuthenticationToken(userInfomation.getUsername(), userInfomation.getPassword());

        return getAuthenticationManager().authenticate(fetchAuthenticationToken);

    }
}
