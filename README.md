# 통합 회원 관리 시스템

## Notes.

Spring Security의 구성방안
- 선언적 방식 : entryPoint/provider/authenticationManager를 dsl api 기반의 "객체구현 및 선언적 방식"
- 프로그래밍 방식 : map/db기반의 유연한 변경점 관리를 위한 "동적 관리 방식"(데이터의 관리를 Map기반 or DB기반)

## 1. UserDetails의 인가정보는 문자열 기반이 아닌 DB 기반 

`security/service/FormUserDetailService`

```java
List<GrantedAuthority> authorities = account.getUserRoles()
                .stream()
                .map(Role::getRoleName)
                .collect(Collectors.toSet())
                .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        ModelMapper mapper = new ModelMapper();
        AccountDto accountDto = mapper.map(account, AccountDto.class);
```

## 2. 회원가입 : DB 기반의 권한 생성

`users/service`

```java
Role role = roleRepository.findByRoleName("ROLE_USER");
```

## 3. 관리자 계정 : 리스너(편의를 위한 자동 생성, 실무에는 적용대상 아님)

`security/listener`

```java
private void setupData() {
        HashSet<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        roles.add(adminRole);
        createUserIfNotFound("admin", "admin@admin.com", "pass", roles);
    }
```