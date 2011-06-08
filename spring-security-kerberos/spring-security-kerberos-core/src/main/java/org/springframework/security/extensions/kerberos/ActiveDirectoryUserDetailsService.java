/*
 * Copyright 2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.extensions.kerberos;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

/**
 * @author Grant Cermak
 * @since 1.1
 * @version $Id$
 */
public class ActiveDirectoryUserDetailsService {

    protected ActiveDirectorySecurityIntegration securityIntegration;
    private ActiveDirectoryAuthoritiesPopulator authoritiesPopulator;

    protected byte[] token;

    public void setToken(byte[] token) {
        this.token = token;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<String> groupSids = securityIntegration.getUserGroupSids(token);

        return new User(username, new String(token), true, true,
            true, true, authoritiesPopulator.getGrantedAuthorities(groupSids));
    }

    public void setSecurityIntegration(ActiveDirectorySecurityIntegration securityIntegration) {
        this.securityIntegration = securityIntegration;
    }

    public void setAuthoritiesPopulator(ActiveDirectoryAuthoritiesPopulator authoritiesPopulator) {
        this.authoritiesPopulator = authoritiesPopulator;
    }
}
