package io.pap;

import com.sun.jna.Pointer;

/**
 * Root Ed25519 keypair bound to the human principal.
 * Implements {@link AutoCloseable} for use in try-with-resources.
 */
public final class PrincipalKeypair implements AutoCloseable {

    private final Pointer handle;

    private PrincipalKeypair(Pointer h) {
        this.handle = h;
    }

    /** Generate a new random principal keypair. */
    public static PrincipalKeypair generate() {
        Pointer h = PapLib.INSTANCE.pap_keypair_generate();
        if (h == null) throw PapException.fromLastError("keypair_generate");
        return new PrincipalKeypair(h);
    }

    /**
     * Reconstruct from 32 raw secret-key bytes.
     *
     * @param bytes exactly 32 bytes
     */
    public static PrincipalKeypair fromSecretBytes(byte[] bytes) {
        if (bytes.length != 32)
            throw new IllegalArgumentException("Secret key must be exactly 32 bytes");
        Pointer h = PapLib.INSTANCE.pap_keypair_from_bytes(bytes, bytes.length);
        if (h == null) throw PapException.fromLastError("keypair_from_bytes");
        return new PrincipalKeypair(h);
    }

    /** The {@code did:key} identifier derived from this keypair. */
    public String did() {
        Pointer ptr = PapLib.INSTANCE.pap_keypair_did(handle);
        if (ptr == null) throw PapException.fromLastError("keypair_did");
        String s = ptr.getString(0);
        PapLib.INSTANCE.pap_string_free(ptr);
        return s;
    }

    /** The raw 32-byte public key. */
    public byte[] publicKeyBytes() {
        byte[] buf = new byte[32];
        if (PapLib.INSTANCE.pap_keypair_public_bytes(handle, buf) != 0)
            throw PapException.fromLastError("keypair_public_bytes");
        return buf;
    }

    /** Sign arbitrary bytes; returns the 64-byte Ed25519 signature. */
    public byte[] sign(byte[] message) {
        byte[] sig = new byte[64];
        if (PapLib.INSTANCE.pap_keypair_sign(handle, message, message.length, sig) != 0)
            throw PapException.fromLastError("keypair_sign");
        return sig;
    }

    /** Package-private: expose the raw Pointer for use by other classes. */
    Pointer raw() { return handle; }

    @Override
    public void close() {
        PapLib.INSTANCE.pap_keypair_free(handle);
    }
}
