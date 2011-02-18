package com.fsck.k9.mail.transport.ntlm;

/* jcifs smb client library in Java
 * Copyright (C) 2002  "Michael B. Allen" <jcifs at samba dot org>
 *                 "Eric Glass" <jcifs at samba dot org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Represents an NTLMSSP Type-3 message.
 */
public class Type3Message extends NtlmMessage {
    private static final int DEFAULT_FLAGS = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;
    private static final SecureRandom RANDOM = new SecureRandom();

    private String domain;
    private String user;
    private String workstation = DEFAULT_WORKSTATION;
    private byte[] sessionKey = null; // always NULL

    private byte[] lmResponse;
    private byte[] ntResponse;

    /**
     * Creates a Type-3 message in response to the given Type-2 message.
     * 
     * @param type2
     *            The Type-2 message which this represents a response to.
     * @param password
     *            The password to use when constructing the response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is taking place.
     */
    public Type3Message(Type2Message type2, String password, String domain, String user, String workstation, int flags) {
        setFlags(flags | getDefaultFlags(type2));
        this.workstation = workstation;
        this.domain = domain;
        this.user = user;

        try {
            // this.lmResponse = ResponseUtil.getLMResponse(password, type2.getChallenge());
            // this.ntResponse = ResponseUtil.getNTLMResponse(password, type2.getChallenge());
            byte[] clientChallenge = new byte[8];
            RANDOM.nextBytes(clientChallenge);
            this.lmResponse = ResponseUtil.getLMv2Response(domain, user, password, type2.getChallenge(),
                    clientChallenge);
            RANDOM.nextBytes(clientChallenge);
            this.ntResponse = ResponseUtil.getNTLMv2Response(domain, user, password, type2.getTargetInformation(),
                    type2.getChallenge(), clientChallenge);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Creates a Type-3 message with the specified parameters.
     * 
     * @param flags
     *            The flags to apply to this message.
     * @param lmResponse
     *            The LanManager/LMv2 response.
     * @param ntResponse
     *            The NT/NTLMv2 response.
     * @param domain
     *            The domain in which the user has an account.
     * @param user
     *            The username for the authenticating user.
     * @param workstation
     *            The workstation from which authentication is taking place.
     */
    public Type3Message(int flags, byte[] lmResponse, byte[] ntResponse, String domain, String user, String workstation) {
        setFlags(flags);
        this.lmResponse = lmResponse;
        this.ntResponse = ntResponse;
        this.domain = domain;
        this.user = user;
        this.workstation = workstation;
    }

    public byte[] toByteArray() {
        try {
            int flags = getFlags();
            boolean unicode = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
            String oem = unicode ? null : getOEMEncoding();
            String domainName = domain;
            byte[] domain = null;
            if (domainName != null && domainName.length() != 0) {
                domain = unicode ? domainName.getBytes(UNI_ENCODING) : domainName.getBytes(oem);
            }
            int domainLength = (domain != null) ? domain.length : 0;
            String userName = user;
            byte[] user = null;
            if (userName != null && userName.length() != 0) {
                user = unicode ? userName.getBytes(UNI_ENCODING) : userName.toUpperCase().getBytes(oem);
            }
            int userLength = (user != null) ? user.length : 0;
            String workstationName = workstation;
            byte[] workstation = null;
            if (workstationName != null && workstationName.length() != 0) {
                workstation = unicode ? workstationName.getBytes(UNI_ENCODING) : workstationName.toUpperCase()
                        .getBytes(oem);
            }
            int workstationLength = (workstation != null) ? workstation.length : 0;
            int lmLength = (lmResponse != null) ? lmResponse.length : 0;
            int ntLength = (ntResponse != null) ? ntResponse.length : 0;
            int keyLength = (sessionKey != null) ? sessionKey.length : 0;
            byte[] type3 = new byte[64 + domainLength + userLength + workstationLength + lmLength + ntLength
                    + keyLength];
            System.arraycopy(NTLMSSP_SIGNATURE, 0, type3, 0, 8);
            writeULong(type3, 8, 3);
            int offset = 64;
            writeSecurityBuffer(type3, 12, offset, lmResponse);
            offset += lmLength;
            writeSecurityBuffer(type3, 20, offset, ntResponse);
            offset += ntLength;
            writeSecurityBuffer(type3, 28, offset, domain);
            offset += domainLength;
            writeSecurityBuffer(type3, 36, offset, user);
            offset += userLength;
            writeSecurityBuffer(type3, 44, offset, workstation);
            offset += workstationLength;
            writeSecurityBuffer(type3, 52, offset, sessionKey);
            writeULong(type3, 60, flags);
            return type3;
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    public String toString() {
        return "Type3Message[domain=" + domain + ",user=" + user + ",workstation=" + workstation + ",lmResponse="
                + (lmResponse == null ? "null" : "<" + lmResponse.length + " bytes>") + ",ntResponse="
                + (ntResponse == null ? "null" : "<" + ntResponse.length + " bytes>") + ",sessionKey="
                + (sessionKey == null ? "null" : "<" + sessionKey.length + " bytes>") + "]";
    }

    /**
     * Returns the default flags for a generic Type-3 message in the current environment.
     * 
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags() {
        return DEFAULT_FLAGS;
    }

    /**
     * Returns the default flags for a Type-3 message created in response to the given Type-2 message in the current
     * environment.
     * 
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags(Type2Message type2) {
        if (type2 == null)
            return DEFAULT_FLAGS;
        int flags = NTLMSSP_NEGOTIATE_NTLM;
        flags |= ((type2.getFlags() & NTLMSSP_NEGOTIATE_UNICODE) != 0) ? NTLMSSP_NEGOTIATE_UNICODE
                : NTLMSSP_NEGOTIATE_OEM;
        return flags;
    }
}