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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @author Grant Cermak
 * @since 1.1
 * @version $Id$
 *
 * This class works with the SpnegoAuthenticationProcessingFilter
 */
public class ActiveDirectoryAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private KerberosTicketValidator ticketValidator;
    private ActiveDirectoryUserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public void setUserDetailsService(ActiveDirectoryUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setTicketValidator(KerberosTicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
        byte[] token = auth.getToken();

        LOG.debug("Try to validate Kerberos Token");
        String username = this.ticketValidator.validateTicket(token);
        LOG.debug("Succesfully validated " + username);

        userDetailsService.setToken(token);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        userDetailsChecker.check(userDetails);

        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.addAll(userDetails.getAuthorities());

        return new KerberosServiceRequestToken(userDetails, authorities, token);
    }

    @Override
    public boolean supports(Class<? extends Object> auth) {
        return KerberosServiceRequestToken.class.isAssignableFrom(auth);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.ticketValidator, "ticketValidator must be specified");
        Assert.notNull(this.userDetailsService, "userDetailsService must be specified");
    }

    private static final Log LOG = LogFactory.getLog(KerberosServiceAuthenticationProvider.class);
}
