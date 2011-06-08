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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link ActiveDirectoryAuthenticationProvider}
 *
 * @author Grant Cermak
 * @since 1.1
 * @version $Id$
 */
public class ActiveDirectoryAuthenticationProviderTest {

    private ActiveDirectoryAuthenticationProvider provider;
    private ActiveDirectoryUserDetailsService userDetailsService;
    private KerberosTicketValidator ticketValidator;
    private ActiveDirectorySecurityIntegration securityIntegration;
    private ActiveDirectoryAuthoritiesPopulator authoritiesPopulator;

    private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";
    private static final byte[] TOKEN = "12345".getBytes();
    private static final KerberosServiceRequestToken INPUT_TOKEN = new KerberosServiceRequestToken(TEST_USER, null, TOKEN);
    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true,true, AUTHORITY_LIST);
    private static final List<String> GROUP_SIDS = new ArrayList<String>();

    @Before
    public void before() {
        // mocking
        this.securityIntegration = mock(ActiveDirectorySecurityIntegration.class);
        this.authoritiesPopulator = mock(ActiveDirectoryAuthoritiesPopulator.class);

        this.userDetailsService = mock(ActiveDirectoryUserDetailsService.class);
        this.userDetailsService.setSecurityIntegration(securityIntegration);
        this.userDetailsService.setAuthoritiesPopulator(authoritiesPopulator);

        this.ticketValidator = mock(KerberosTicketValidator.class);

        this.provider = new ActiveDirectoryAuthenticationProvider();
        this.provider.setUserDetailsService(userDetailsService);
        this.provider.setTicketValidator(ticketValidator);
    }

    @Test
    public void testLoginOk() throws Exception {
        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);
        when(ticketValidator.validateTicket(TOKEN)).thenReturn(TEST_USER);
        when(securityIntegration.getUserGroupSids(TOKEN)).thenReturn(GROUP_SIDS);
        when(authoritiesPopulator.getGrantedAuthorities(GROUP_SIDS)).thenReturn(AUTHORITY_LIST);

        Authentication authenticate = provider.authenticate(INPUT_TOKEN);

        assertNotNull(authenticate);
        assertEquals(TEST_USER, authenticate.getName());
        assertEquals(USER_DETAILS, authenticate.getPrincipal());
        assertEquals(AUTHORITY_LIST, authenticate.getAuthorities());
    }
}
