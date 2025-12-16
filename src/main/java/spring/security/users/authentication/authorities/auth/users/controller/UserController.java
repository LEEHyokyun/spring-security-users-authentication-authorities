package spring.security.users.authentication.authorities.auth.users.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import spring.security.users.authentication.authorities.auth.users.domain.entity.Account;
import spring.security.users.authentication.authorities.auth.users.domain.vo.UserInfomation;
import spring.security.users.authentication.authorities.auth.users.service.UserService;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @GetMapping("/signup")
    public String signup(){
        return "signup";
    }

    //회원가입
    @PostMapping("/signup")
    public Account signup(@RequestBody UserInfomation userInfomation){
        ModelMapper modelMapper = new ModelMapper();
        Account account =  modelMapper.map(userInfomation, Account.class);
        account.setPassword(passwordEncoder.encode(userInfomation.getPassword()));

        userService.signUp(account);

        return account;
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "exception", required = false) String exception,
            Model model
    ){
        //give to thymeleaf
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "login";
    }

    @GetMapping("/denied")
    public String denied(
            @RequestParam(value = "exception", required = false) String exception,
            @AuthenticationPrincipal UserInfomation userInformation,
            Model model
    ){
        model.addAttribute("error", exception);
        model.addAttribute("userInformation", userInformation);
        model.addAttribute("user", userInformation);
        model.addAttribute("userId", userInformation.getId());

        return "denied";
    }
}
