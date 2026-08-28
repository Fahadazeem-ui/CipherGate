package dev.ciphergate.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Versioned PBKDF2 hashes. No password or reversible value is written to disk. */
public final class PasswordHasher {
    private static final String FORMAT = "cg1";
    private static final String ALGORITHM_LABEL = "pbkdf2-sha512";
    private static final String JCA_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final SecureRandom random = new SecureRandom();
    private volatile SecuritySettings settings;

    public PasswordHasher(final SecuritySettings settings) {
        this.settings = settings;
    }

    public void setSettings(final SecuritySettings settings) {
        this.settings = settings;
    }

    public String hash(final char[] password) throws GeneralSecurityException {
        final SecuritySettings current = settings;
        final byte[] salt = new byte[current.saltBytes()];
        random.nextBytes(salt);
        final byte[] digest = derive(password, salt, current.pbkdf2Iterations(), current.hashBits(), current.pepper());
        try {
            return String.join("$", FORMAT, ALGORITHM_LABEL, String.valueOf(current.pbkdf2Iterations()),
                    ENCODER.encodeToString(salt), ENCODER.encodeToString(digest));
        } finally {
            Arrays.fill(digest, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    public Verification verify(final char[] password, final String storedHash) throws GeneralSecurityException {
        final String[] parts = storedHash.split("\\$", -1);
        if (parts.length != 5 || !FORMAT.equals(parts[0]) || !ALGORITHM_LABEL.equals(parts[1])) {
            return Verification.invalid();
        }

        final int iterations;
        final byte[] salt;
        final byte[] expected;
        try {
            iterations = Integer.parseInt(parts[2]);
            salt = DECODER.decode(parts[3]);
            expected = DECODER.decode(parts[4]);
        } catch (final IllegalArgumentException invalidEncoding) {
            return Verification.invalid();
        }
        if (iterations < 100_000 || iterations > 2_000_000 || salt.length < 16 || expected.length < 32 || expected.length > 128) {
            return Verification.invalid();
        }

        final SecuritySettings current = settings;
        final byte[] actual = derive(password, salt, iterations, expected.length * Byte.SIZE, current.pepper());
        try {
            final boolean valid = MessageDigest.isEqual(expected, actual);
            return new Verification(valid, valid && iterations < current.pbkdf2Iterations());
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(actual, (byte) 0);
        }
    }

    private byte[] derive(final char[] password, final byte[] salt, final int iterations, final int bits, final String pepper)
            throws GeneralSecurityException {
        final char[] pepperChars = pepper.toCharArray();
        final char[] material = Arrays.copyOf(password, password.length + pepperChars.length);
        System.arraycopy(pepperChars, 0, material, password.length, pepperChars.length);
        Arrays.fill(pepperChars, '\0');

        final PBEKeySpec keySpec = new PBEKeySpec(material, salt, iterations, bits);
        Arrays.fill(material, '\0');
        try {
            return SecretKeyFactory.getInstance(JCA_ALGORITHM).generateSecret(keySpec).getEncoded();
        } finally {
            keySpec.clearPassword();
        }
    }

    public record Verification(boolean valid, boolean needsUpgrade) {
        private static Verification invalid() {
            return new Verification(false, false);
        }
    }
}
