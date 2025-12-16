package spring.security.users.authentication.authorities.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import spring.security.users.authentication.authorities.auth.config.handler.denied.FormAccessDeniedHandler;
import spring.security.users.authentication.authorities.auth.config.handler.exception.FetchAccessDeniedHandler;
import spring.security.users.authentication.authorities.auth.config.handler.exception.FetchAuthenticationEntryPoint;
import spring.security.users.authentication.authorities.auth.config.handler.failure.FetchAuthenticationFailureHandler;
import spring.security.users.authentication.authorities.auth.config.handler.failure.FormAuthenticationFailureHandler;
import spring.security.users.authentication.authorities.auth.config.handler.success.FetchAuthenticationSuccessHandler;
import spring.security.users.authentication.authorities.auth.config.handler.success.FormAuthenticationSuccessHandler;
import spring.security.users.authentication.authorities.auth.config.provider.FetchAuthenticationProvider;
import spring.security.users.authentication.authorities.auth.dsl.FetchApiDsl;

@Slf4j
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;
    private final FetchAuthenticationProvider fetchAuthenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final FormAuthenticationFailureHandler formAuthenticationFailureHandler;
    private final FetchAuthenticationSuccessHandler fetchAuthenticationSuccessHandler;
    private final FetchAuthenticationFailureHandler fetchAuthenticationFailureHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/css/**", "/images/**", "/js/**", "/webjars/**", "/favicon/**", "/*/icon/-*").permitAll()
                .requestMatchers("/", "/login", "/login*", "/signup").permitAll()
                .requestMatchers("/user").hasAuthority("ROLE_USER")
                .anyRequest().authenticated()
        )
                .formLogin(form -> form.loginPage("/login")
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .successHandler(formAuthenticationSuccessHandler)
                        .failureHandler(formAuthenticationFailureHandler)
                        .permitAll())
                //.userDetailsService(userDetailsService)
                .authenticationProvider(authenticationProvider)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(new FormAccessDeniedHandler("/denied"))
                )
        ;

        //th:action="@{/login} method=post" --csrf

        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain fetchSecurityFilterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(fetchAuthenticationProvider);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http
                .securityMatcher("/fetch/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/webjars/**", "/favicon/**", "/*/icon/-*").permitAll()
                        .requestMatchers("/fetch/login").permitAll()
                        .anyRequest().authenticated()
                )
                //.csrf(AbstractHttpConfigurer::disable)
                //.addFilterBefore(fetchAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .authenticationManager(authenticationManager)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new FetchAuthenticationEntryPoint())
                        .accessDeniedHandler(new FetchAccessDeniedHandler())
                )
                .with(new FetchApiDsl<>(), dsl -> dsl
                                .fetchSuccessHandler(fetchAuthenticationSuccessHandler)
                                .fetchFailureHandler(fetchAuthenticationFailureHandler)
                                .loginPage("/fetch/login") //get
                                .loginProcessingUrl("/fetch/login") //post
                        )
        ;

        //th:action="@{/login} method=post" --csrf

        return http.build();
    }

//    private FetchAuthenticationFilter fetchAuthenticationFilter(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) throws Exception {
//        //httpSecurity -> session/context(영속화)
//        FetchAuthenticationFilter fetchAuthenticationFilter = new FetchAuthenticationFilter(httpSecurity);
//        fetchAuthenticationFilter.setAuthenticationManager(authenticationManager);
//
//        //handler
//        fetchAuthenticationFilter.setAuthenticationSuccessHandler(fetchAuthenticationSuccessHandler);
//        fetchAuthenticationFilter.setAuthenticationFailureHandler(fetchAuthenticationFailureHandler);
//
//        return fetchAuthenticationFilter;
//    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user =  User.withUsername("user").password("{noop}1234").roles("USER").build();
//
//        return new InMemoryUserDetailsManager(user);
//    }
}
