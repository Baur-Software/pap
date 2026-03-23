package io.pap;

import com.sun.jna.Pointer;

/**
 * Single-use proof authorizing a session.
 * Bound to: target DID + action + nonce.
 */
public final class CapabilityToken implements AutoCloseable {

    private final Pointer handle;

    private CapabilityToken(Pointer h) {
        this.handle = h;
    }

    /**
     * Mint a new capability token.
     *
     * @param expiresAtRfc3339 RFC 3339 expiry timestamp
     */
    public static CapabilityToken mint(
            String targetDid, String action,
            String issuerDid, String expiresAtRfc3339) {
        Pointer h = PapLib.INSTANCE.pap_token_mint(
                targetDid, action, issuerDid, expiresAtRfc3339);
        if (h == null) throw PapException.fromLastError("token_mint");
        return new CapabilityToken(h);
    }

    /** Sign the token with the issuer's keypair. */
    public void sign(PrincipalKeypair keypair) {
        if (PapLib.INSTANCE.pap_token_sign(handle, keypair.raw()) != 0)
            throw PapException.fromLastError("token_sign");
    }

    /** Serialize to a JSON string. */
    public String toJson() {
        Pointer ptr = PapLib.INSTANCE.pap_token_to_json(handle);
        if (ptr == null) throw PapException.fromLastError("token_to_json");
        String s = ptr.getString(0);
        PapLib.INSTANCE.pap_string_free(ptr);
        return s;
    }

    /** Deserialize from a JSON string. */
    public static CapabilityToken fromJson(String json) {
        Pointer h = PapLib.INSTANCE.pap_token_from_json(json);
        if (h == null) throw PapException.fromLastError("token_from_json");
        return new CapabilityToken(h);
    }

    Pointer raw() { return handle; }

    @Override
    public void close() {
        PapLib.INSTANCE.pap_token_free(handle);
    }
}
