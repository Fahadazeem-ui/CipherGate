package dev.ciphergate.auth;

/** The complete persistent state for one UUID. Password hashes are versioned separately. */
public record Account(
        String passwordHash,
        long createdAt,
        long passwordChangedAt,
        int failedAttempts,
        long lockedUntil
) {
    public boolean isLocked(final long now) {
        return lockedUntil > now;
    }

    public Account successfulLogin(final String upgradedHash, final long now) {
        return new Account(
                upgradedHash == null ? passwordHash : upgradedHash,
                createdAt,
                upgradedHash == null ? passwordChangedAt : now,
                0,
                0
        );
    }

    public Account failedLogin(final long now, final SecuritySettings settings) {
        final int nextAttempts = failedAttempts + 1;
        if (nextAttempts >= settings.maxFailedAttempts()) {
            return new Account(
                    passwordHash,
                    createdAt,
                    passwordChangedAt,
                    0,
                    now + settings.lockoutMinutes() * 60_000L
            );
        }
        return new Account(passwordHash, createdAt, passwordChangedAt, nextAttempts, lockedUntil);
    }

    public Account unlocked() {
        return new Account(passwordHash, createdAt, passwordChangedAt, 0, 0);
    }
}
