package com.fsck.k9.mail.transport.ntlm;

/**
 * Flags used during negotiation of NTLMSSP authentication.
 */
public interface NtlmFlags {
    public static final int NTLMSSP_NEGOTIATE_UNICODE = 0x00000001;
    public static final int NTLMSSP_NEGOTIATE_OEM = 0x00000002;
    public static final int NTLMSSP_NEGOTIATE_NTLM = 0x00000200;
    public static final int NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED =
        0x00001000;
    public static final int NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED =
        0x00002000;
    static final String DEFAULT_WORKSTATION = "android";
}