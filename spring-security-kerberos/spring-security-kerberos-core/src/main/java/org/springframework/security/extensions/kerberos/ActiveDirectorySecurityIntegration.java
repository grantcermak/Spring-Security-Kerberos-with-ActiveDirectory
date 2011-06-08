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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;
import org.jaaslounge.decoding.spnego.SpnegoConstants;
import org.jaaslounge.decoding.spnego.SpnegoInitToken;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author Grant Cermak
 * @since 1.1
 * @version $Id$
 */
public class ActiveDirectorySecurityIntegration  {
    /**
     * @param token is the Spnego header passed from the client to the server, it is base64 decoded in the SpnegoAuthenticationProcessingFilter
     * @return the group SIDs to which the user belongs decoded from the PAC
     */
    public List<String> getUserGroupSids(byte [] token) {
        List<String> sids = new ArrayList<String>();

        try {
            // Parse the ASN.1 byte stream into the SpengoInitToken, of which we need to get at the mechanism token
            // http://msdn.microsoft.com/en-us/library/ms995330.aspx
            SpnegoInitToken spnegoToken = new SpnegoInitToken(token);
            String mechanism = spnegoToken.getMechanism();

            // If the mechanism token is the Microsoft Kerberos Oid or the MIT Kerberos v5 Oid then we proceed
            if (SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism)
                    || SpnegoConstants.LEGACY_KERBEROS_MECHANISM.equals(mechanism)) {

                if (ticketValidator instanceof SunJaasKerberosTicketValidator) {
                    byte[] mechanismToken = spnegoToken.getMechanismToken();

                    // subject is based on the keytab configured in the ticketValidator
                    Subject subject = ((SunJaasKerberosTicketValidator) ticketValidator).getServiceSubject();

                    // creds are the Kerberos decryption keys available to the subject bound to the keytab file
                    Set<KerberosKey> creds = subject.getPrivateCredentials(KerberosKey.class);
                    KerberosKey[] keys = creds.toArray(new KerberosKey[creds.size()]);

                    // decrypt the Kerberos ticket encrypted for the server (this is the magic/expensive step!)
                    Security.addProvider(new BouncyCastleProvider());
                    KerberosToken kerberosToken = new KerberosToken(mechanismToken, keys);

                    // the authorization data bound in the kerberos ticket has the PAC (Privileged Attribute Certificate)
                    // http://blogs.msdn.com/b/openspecification/archive/2009/04/24/understanding-microsoft-kerberos-pac-validation.aspx
                    List<KerberosAuthData> authorizations = kerberosToken.getTicket().getEncData().getUserAuthorizations();

                    for (KerberosAuthData authorization : authorizations) {
                        // if this isn't the PAC then we can skip past it
                        if (!(authorization instanceof KerberosPacAuthData))
                            continue;

                        // we've got the PAC so crack it open and collect up all the SIDs
                        // a SID is a unique identifier in Active Directory that has the form
                        // S-1-5-21-185937884-2362668773-3192785854-1139
                        // PacUtility.binarySidToStringSid converts the string representation of the
                        // byte data into the more readable/familiar form
                        PacLogonInfo logonInfo = ((KerberosPacAuthData) authorization).getPac().getLogonInfo();

                        if (logonInfo.getGroupSid() != null)
                            sids.add(PacUtility.binarySidToStringSid(logonInfo.getGroupSid().toString()));
                        for (PacSid pacSid : logonInfo.getGroupSids())
                            sids.add(PacUtility.binarySidToStringSid(pacSid.toString()));
                        for (PacSid pacSid : logonInfo.getExtraSids())
                            sids.add(PacUtility.binarySidToStringSid(pacSid.toString()));
                        for (PacSid pacSid : logonInfo.getResourceGroupSids())
                            sids.add(PacUtility.binarySidToStringSid(pacSid.toString()));
                    }
                }
            }
        } catch (DecodingException e) {
            throw new RuntimeException("SPNEGO Decoding failed", e);
        } catch (Exception e) {
            throw new RuntimeException("Unknown failure", e);
        }

        return sids;
    }

    public void setTicketValidator(KerberosTicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    private KerberosTicketValidator ticketValidator;
}

