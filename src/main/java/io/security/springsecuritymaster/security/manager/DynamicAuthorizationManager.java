package io.security.springsecuritymaster.security.manager;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.security.mapper.MapBasedEndPointMapper;
import io.security.springsecuritymaster.security.mapper.PersistentDBBasedEndPointMapper;
import io.security.springsecuritymaster.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
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
public class DynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;
    //private static final AuthorizationDecision DENY = new AuthorizationDecision(false); //default : 거부
    private final AuthorizationDecision GRANT = new AuthorizationDecision(true); //default : 승인
    private final HandlerMappingIntrospector handlerMappingIntrospector;
    private final ResourcesRepository resourcesRepository;

    @PostConstruct
    public void mapping(){
        //strategy
        //DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new MapBasedEndPointMapper());
        DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new PersistentDBBasedEndPointMapper(resourcesRepository));

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
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext request) {

        for(RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry: this.mappings){

            RequestMatcher matcher = entry.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request.getRequest());

            if(matchResult.isMatch()){
                AuthorizationManager<RequestAuthorizationContext> manager = entry.getEntry();

                return manager.check(authentication, new RequestAuthorizationContext(request.getRequest(), matchResult.getVariables()));
            }
        }

        //request != mappings -> 거부? 허용?
        return GRANT;  //특히 개발/테스트 환경에서 권한체계가 구성이 되기 전에 요청에 대한 처리방법을 최초 GRANT(예외처리X)로 설정할 수 있다.
    }

    //authorization manager 구현체 선택 및 위임
    private AuthorizationManager<RequestAuthorizationContext> endPointAuthroizationManager(String role) {
        if(role != null){
            if(role.startsWith("ROLE")){
                return AuthorityAuthorizationManager.hasAuthority(role); //인증매니저
            }else{
                return new WebExpressionAuthorizationManager(role);  //표현식
            }
        }

        return null;
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }


}
