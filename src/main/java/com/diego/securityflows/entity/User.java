package com.diego.securityflows.entity;

import com.diego.securityflows.common.Constants;
import com.diego.securityflows.domain.Role;
import com.diego.securityflows.domain.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import javax.persistence.*;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
//@Entity
//@Table(name = "SF_USER")
public class User implements UserDetails {

    //@Id
    //@GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstname;

    private String lastname;

    private String email;

    private String password;

    private List<Role> roles;

    private UserStatus status;

    public User(String email, String password) {
        this.email = email;
        this.password = password;
        this.roles = getDefaultRole();
    }

    public User(String email, String password, List<String> roles) {
        this.email = email;
        this.password = password;
        this.roles = CollectionUtils.isEmpty(roles) ? getDefaultRole() : Role.fromString(roles);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(r -> new SimpleGrantedAuthority(Constants.ROLE_STARTER + r.name()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.status.equals(UserStatus.ACTIVE);
    }

    public static List<Role> getDefaultRole() {
        return Collections.singletonList(Role.USER);
    }
}
