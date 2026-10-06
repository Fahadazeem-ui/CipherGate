package dev.ciphergate.auth;

/**
 * The complete persistent state for one UUID. Password hashes are versioned
 * separately. The allowed IP is blank when the account has no IP lock.
 */
public record Account(
        String passwordHash,
        long createdAt,
        long passwordChangedAt,
        int failedAttempts,
        long lockedUntil,
        String allowedIp
) {
    public Account {
        allowedIp = allowedIp == null ? "" : allowedIp;
    }

    public boolean isLocked(final long now) {
        return lockedUntil > now;
    }

    public boolean hasIpLock() {
        return !allowedIp.isBlank();
    }

    public Account successfulLogin(final String upgradedHash, final long now) {
        return new Account(
                upgradedHash == null ? passwordHash : upgradedHash,
                createdAt,
                upgradedHash == null ? passwordChangedAt : now,
                0,
                0,
                allowedIp
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
                    now + settings.lockoutMinutes() * 60_000L,
                    allowedIp
            );
        }
        return new Account(passwordHash, createdAt, passwordChangedAt, nextAttempts, lockedUntil, allowedIp);
    }

    public Account unlocked() {
        return new Account(passwordHash, createdAt, passwordChangedAt, 0, 0, allowedIp);
    }

    public Account withAllowedIp(final String ip) {
        return new Account(passwordHash, createdAt, passwordChangedAt, failedAttempts, lockedUntil,
                ip == null ? "" : ip);
    }

    public Account withoutAllowedIp() {
        return new Account(passwordHash, createdAt, passwordChangedAt, failedAttempts, lockedUntil, "");
    }
}
