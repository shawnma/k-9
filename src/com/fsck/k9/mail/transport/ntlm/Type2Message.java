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

/**
 * Represents an NTLMSSP Type-2 message.
 */
public class Type2Message extends NtlmMessage {

    private static final int DEFAULT_FLAGS;

    private static final String DEFAULT_DOMAIN;

    private static final byte[] DEFAULT_TARGET_INFORMATION = null;

    private byte[] challenge;

    private String target;

    private byte[] context;

    private byte[] targetInformation;

    static {
        DEFAULT_FLAGS = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;
        DEFAULT_DOMAIN = "";
    }


    /**
     * Creates a Type-2 message using the given raw Type-2 material.
     *
     * @param material The raw Type-2 material used to construct this message.
     * @throws IOException If an error occurs while parsing the material.
     */
    public Type2Message(byte[] material) throws IOException {
        parse(material);
    }

    /**
     * Returns the challenge for this message.
     *
     * @return A <code>byte[]</code> containing the challenge.
     */
    public byte[] getChallenge() {
        return challenge;
    }

    /**
     * Sets the challenge for this message.
     *
     * @param challenge The challenge from the domain controller/server.
     */
    public void setChallenge(byte[] challenge) {
        this.challenge = challenge;
    }

    /**
     * Returns the authentication target.
     *
     * @return A <code>String</code> containing the authentication target.
     */
    public String getTarget() {
        return target;
    }

    /**
     * Sets the authentication target.
     *
     * @param target The authentication target.
     */
    public void setTarget(String target) {
        this.target = target;
    }

    /**
     * Returns the target information block.
     *
     * @return A <code>byte[]</code> containing the target information block.
     * The target information block is used by the client to create an
     * NTLMv2 response.
     */ 
    public byte[] getTargetInformation() {
        return targetInformation;
    }

    /**
     * Sets the target information block.
     * The target information block is used by the client to create
     * an NTLMv2 response.
     * 
     * @param targetInformation The target information block.
     */
    public void setTargetInformation(byte[] targetInformation) {
        this.targetInformation = targetInformation;
    }

    /**
     * Returns the local security context.
     *
     * @return A <code>byte[]</code> containing the local security
     * context.  This is used by the client to negotiate local
     * authentication.
     */
    public byte[] getContext() {
        return context;
    }

    /**
     * Sets the local security context.  This is used by the client
     * to negotiate local authentication.
     *
     * @param context The local security context.
     */
    public void setContext(byte[] context) {
        this.context = context;
    }

    public String toString() {
        String target = getTarget();
        byte[] challenge = getChallenge();
        byte[] context = getContext();
        byte[] targetInformation = getTargetInformation();

        return "Type2Message[target=" + target +
            ",challenge=" + (challenge == null ? "null" : "<" + challenge.length + " bytes>") +
            ",context=" + (context == null ? "null" : "<" + context.length + " bytes>") +
            ",targetInformation=" + (targetInformation == null ? "null" : "<" + targetInformation.length + " bytes>") ;
    }

    /**
     * Returns the default flags for a generic Type-2 message in the
     * current environment.
     *
     * @return An <code>int</code> containing the default flags.
     */
    public static int getDefaultFlags() {
        return DEFAULT_FLAGS;
    }

    /**
     * Returns the default domain from the current environment.
     *
     * @return A <code>String</code> containing the domain.
     */
    public static String getDefaultDomain() {
        return DEFAULT_DOMAIN;
    }

    public static byte[] getDefaultTargetInformation() {
        return DEFAULT_TARGET_INFORMATION;
    }

    private void parse(byte[] material) throws IOException {
        for (int i = 0; i < 8; i++) {
            if (material[i] != NTLMSSP_SIGNATURE[i]) {
                throw new IOException("Not an NTLMSSP message.");
            }
        }
        if (readULong(material, 8) != 2) {
            throw new IOException("Not a Type 2 message.");
        }
        int flags = readULong(material, 20);
        setFlags(flags);
        String target = null;
        byte[] bytes = readSecurityBuffer(material, 12);
        if (bytes.length != 0) {
            target = new String(bytes,
                    ((flags & NTLMSSP_NEGOTIATE_UNICODE) != 0) ?
                            UNI_ENCODING : getOEMEncoding());
        }
        setTarget(target);
        for (int i = 24; i < 32; i++) {
            if (material[i] != 0) {
                byte[] challenge = new byte[8];
                System.arraycopy(material, 24, challenge, 0, 8);
                setChallenge(challenge);
                break;
            }
        }
        int offset = readULong(material, 16); // offset of targetname start
        if (offset == 32 || material.length == 32) return;
        for (int i = 32; i < 40; i++) {
            if (material[i] != 0) {
                byte[] context = new byte[8];
                System.arraycopy(material, 32, context, 0, 8);
                setContext(context);
                break;
            }
        }
        if (offset == 40 || material.length == 40) return;
        bytes = readSecurityBuffer(material, 40);
        if (bytes.length != 0) setTargetInformation(bytes);
    }

    @Override
    public byte[] toByteArray() {
        return null;
    }

}