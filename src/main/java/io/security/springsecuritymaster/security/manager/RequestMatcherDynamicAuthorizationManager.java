package io.security.springsecuritymaster.security.manager;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.security.mapper.PersistentDBBasedEndPointMapper;
import io.security.springsecuritymaster.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class RequestMatcherDynamicAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;
    //private static final AuthorizationDecision DENY = new AuthorizationDecision(false); //default : 거부
    private final AuthorizationDecision GRANT = new AuthorizationDecision(true); //default : 승인
    private final HandlerMappingIntrospector handlerMappingIntrospector;
    private final ResourcesRepository resourcesRepository;
    private final RoleHierarchyImpl roleHierarchy;

    DynamicAuthorizationService dynamicAuthorizationService;

    @PostConstruct
    public void mapping(){
        //strategy
        //DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new MapBasedEndPointMapper());
        dynamicAuthorizationService = new DynamicAuthorizationService(new PersistentDBBasedEndPointMapper(resourcesRepository));

        setMapping();
    }

    private void setMapping(){
        mappings = dynamicAuthorizationService.getEndPointMappings()
                .entrySet().stream()
                .map(entry -> new RequestMatcherEntry<>(
                        new MvcRequestMatcher(handlerMappingIntrospector, entry.getKey()),
                        endPointAuthroizationManager(entry.getValue())
                ))
                .collect(Collectors.toList());
    }

    //request in mapping url인지 확인
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {

        for(RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry: this.mappings){

            RequestMatcher matcher = entry.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request);

            if(matchResult.isMatch()){
                AuthorizationManager<RequestAuthorizationContext> manager = entry.getEntry();

                return manager.check(authentication, new RequestAuthorizationContext(request, matchResult.getVariables()));
            }
        }

        //request != mappings -> 거부? 허용?
        return GRANT;  //특히 개발/테스트 환경에서 권한체계가 구성이 되기 전에 요청에 대한 처리방법을 최초 GRANT(예외처리X)로 설정할 수 있다.
    }

    //authorization manager 구현체 선택 및 위임
    private AuthorizationManager<RequestAuthorizationContext> endPointAuthroizationManager(String role) {
        if(role != null){
            if(role.startsWith("ROLE")){

                AuthorityAuthorizationManager<RequestAuthorizationContext> authorizationManager = AuthorityAuthorizationManager.hasAuthority(role);
                authorizationManager.setRoleHierarchy(roleHierarchy);

                //AuthorityAuthorizationManager.hasAuthority(role);

                return authorizationManager;//인증매니저
            }else{
                DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();
                handler.setRoleHierarchy(roleHierarchy);

                WebExpressionAuthorizationManager webExpressionAuthorizationManager = new WebExpressionAuthorizationManager(role);
                webExpressionAuthorizationManager.setExpressionHandler(handler);

                return webExpressionAuthorizationManager;  //표현식
            }
        }

        return null;
    }

    @Override
    public void verify(Supplier<Authentication> authentication, HttpServletRequest object) {
        AuthorizationManager.super.verify(authentication, object);
    }

    //매핑정보 동시성 문제 방지
    public synchronized void reload(){
        /*
        * 매핑정보 다시 반영
        * mappings = dynamicAuthorizationService.getEndPointMappings()
                .entrySet().stream()
                .map(entry -> new RequestMatcherEntry<>(
                        new MvcRequestMatcher(handlerMappingIntrospector, entry.getKey()),
                        endPointAuthroizationManager(entry.getValue())
                ))
                .collect(Collectors.toList());
        * */
        mappings.clear();
        setMapping();
    }
}
