package org.springframework.security.extensions.kerberos.sample;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.extensions.kerberos.ActiveDirectoryAuthoritiesPopulator;

import java.util.Collection;
import java.util.List;

/**
 * @author Grant Cermak
 * @since 1.1
 * @version $Id$
 */
public class DummyActiveDirectoryAuthoritiesPopulator implements ActiveDirectoryAuthoritiesPopulator {
    @Override
    public Collection<GrantedAuthority> getGrantedAuthorities(List<String> sids) {
        return AuthorityUtils.createAuthorityList("ROLE_USER");
    }
}
