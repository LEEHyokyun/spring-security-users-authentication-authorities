package io.security.springsecuritymaster.admin.service.impl;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.admin.repository.RoleHierarchyRepository;
import io.security.springsecuritymaster.admin.service.RoleHierarchyService;
import io.security.springsecuritymaster.domain.entity.RoleHierarchy;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    //private RoleHierarchyRepository roleHierarchyRepository;

//    @Autowired
//    private void setRoleHierarchyServiceImpl(RoleHierarchyRepository roleHierarchyRepository) {
//        this.roleHierarchyRepository = roleHierarchyRepository;
//    }

    @Transactional
    @Override
    public String findAllRoleHierarchies() {
        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
        StringBuilder hierarchyRole = new StringBuilder();

        //ROLE_MANAGER > ROLE_USER .. 계층순서대로 꺽쇠 기반의 내림차순 정렬
        while (itr.hasNext()) {
            RoleHierarchy roleHierarchy = itr.next();
            if (roleHierarchy.getParent() != null) {
                hierarchyRole.append(roleHierarchy.getParent().getRoleName());
                hierarchyRole.append(" > ");
                hierarchyRole.append(roleHierarchy.getRoleName());
                hierarchyRole.append("\n");
            }
        }
        return hierarchyRole.toString();
    }
}
