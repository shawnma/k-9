package com.fsck.k9.mail.transport.ntlm;

import java.io.IOException;

/**
 * Represents an NTLMSSP Type-1 message.
 */
public class Type1Message extends NtlmMessage {

    private static final int DEFAULT_FLAGS = NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM;

    private static final String DEFAULT_DOMAIN = null;

    private String suppliedDomain;

    private String suppliedWorkstation;

    /**
     * Creates a Type-1 message using default values from the current
     * environment.
     */
    public Type1Message() {
        this(DEFAULT_FLAGS, DEFAULT_DOMAIN, DEFAULT_WORKSTATION);
    }

    /**
     * Creates a Type-1 message with the specified parameters.
     *
     * @param flags The flags to apply to this message.
     * @param suppliedDomain The supplied authentication domain.
     * @param suppliedWorkstation The supplied workstation name.
     */
    public Type1Message(int flags, String suppliedDomain,
            String suppliedWorkstation) {
        setFlags(DEFAULT_FLAGS | flags);
        this.suppliedDomain = suppliedDomain;
        if (suppliedWorkstation == null)
            suppliedWorkstation = DEFAULT_WORKSTATION;
        this.suppliedWorkstation = suppliedWorkstation;
    }


    public byte[] toByteArray() {
        try {
            int flags = getFlags();
            boolean hostInfo = false;
            byte[] domain = new byte[0];
            if (suppliedDomain != null && suppliedDomain.length() != 0) {
                hostInfo = true;
                flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
                domain = suppliedDomain.toUpperCase().getBytes(
                        getOEMEncoding());
            } else {
                flags &= (NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED ^ 0xffffffff);
            }
            byte[] workstation = new byte[0];
            if (suppliedWorkstation != null &&
                    suppliedWorkstation.length() != 0) {
                hostInfo = true;
                flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
                workstation =
                        suppliedWorkstation.toUpperCase().getBytes(
                                getOEMEncoding());
            } else {
                flags &= (NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED ^
                        0xffffffff);
            }
            byte[] type1 = new byte[hostInfo ?
                    (32 + domain.length + workstation.length) : 16];
            System.arraycopy(NTLMSSP_SIGNATURE, 0, type1, 0, 8);
            writeULong(type1, 8, 1);
            writeULong(type1, 12, flags);
            if (hostInfo) {
                writeSecurityBuffer(type1, 16, 32, domain);
                writeSecurityBuffer(type1, 24, 32 + domain.length, workstation);
            }
            return type1;
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage());
        }
    }

    public String toString() {
        return "Type1Message[suppliedDomain=" + (suppliedDomain == null ? "null" : suppliedDomain) +
                ",suppliedWorkstation=" + (suppliedWorkstation == null ? "null" : suppliedWorkstation) +
                "]";
    }
}