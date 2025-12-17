package io.security.springsecuritymaster.security.mapper;

import java.util.Map;

public class PersistentDBBasedEndPointMapper implements EndPointRoleMapper {
    @Override
    public Map<String, String> getUrlToleMapping() {
        return Map.of();
    }
}
