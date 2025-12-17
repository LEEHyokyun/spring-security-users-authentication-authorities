package io.security.springsecuritymaster.security.mapper;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.domain.entity.Resources;
import lombok.RequiredArgsConstructor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public class PersistentDBBasedEndPointMapper implements EndPointRoleMapper {

    private final LinkedHashMap<String, String> urlRoleMappings =  new LinkedHashMap<>();
    private final ResourcesRepository resourcesRepository;

    @Override
    public Map<String, String> getUrlToleMapping() {
        List<Resources> resourcesList = resourcesRepository.findAllResources();

        resourcesList.stream().forEach(resource -> {
            resource.getRoleSet().forEach(role -> {
                urlRoleMappings.put(resource.getResourceName(), role.getRoleName());
            });
        });

        return urlRoleMappings;
    }
}
