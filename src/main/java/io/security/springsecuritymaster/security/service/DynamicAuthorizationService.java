package io.security.springsecuritymaster.security.service;

import io.security.springsecuritymaster.security.mapper.EndPointRoleMapper;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class DynamicAuthorizationService {
    //strategy
    private final EndPointRoleMapper delegate;

    public Map<String,String> getEndPointMappings(){
        return delegate.getUrlToleMapping();
    }
}
