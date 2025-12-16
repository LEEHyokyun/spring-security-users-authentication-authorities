package spring.security.users.authentication.authorities.fetch.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.users.authentication.authorities.auth.users.domain.vo.UserInfomation;

@RestController
@RequestMapping("/fetch")
public class FetchController {
    @PostMapping("/login")
    public String fetchLogin(){
        return "fetch/login";
    }

    @PostMapping("/logout")
    public String fetchLogout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping("/user")
    public UserInfomation fetchUser(@AuthenticationPrincipal UserInfomation userInfomation){
        return userInfomation;
    }

    @GetMapping("/manager")
    public UserInfomation fetchManager(@AuthenticationPrincipal UserInfomation userInfomation){
        return userInfomation;
    }

    @GetMapping("/admin")
    public UserInfomation fetchAdmin(@AuthenticationPrincipal UserInfomation userInfomation){
        return userInfomation;
    }
}
