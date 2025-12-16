package spring.security.users.authentication.authorities.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class PasswordConfig {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        String encodoingId = "bcrypt; //basic
//
//        Map<String,PasswordEncoder> encoders = new HashMap<>();
//        encoders.put(encodoingId, new BCryptPasswordEncoder());
//    }
}
