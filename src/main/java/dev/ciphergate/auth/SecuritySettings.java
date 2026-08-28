package dev.ciphergate.auth;

import org.bukkit.configuration.file.FileConfiguration;

import java.util.Objects;

/** Immutable, validated settings used by the authentication pipeline. */
public record SecuritySettings(
        boolean allowRegistration,
        int timeoutSeconds,
        int maxFailedAttempts,
        int lockoutMinutes,
        int minimumPasswordLength,
        int maximumPasswordLength,
        boolean requireUppercase,
        boolean requireLowercase,
        boolean requireDigit,
        boolean requireSymbol,
        int pbkdf2Iterations,
        int saltBytes,
        int hashBits,
        String pepper,
        boolean blockChatBeforeLogin,
        boolean showGateOnJoin,
        String genericLoginFailure
) {
    public static SecuritySettings from(final FileConfiguration config) {
        Objects.requireNonNull(config, "config");

        final String propertyPepper = System.getProperty("ciphergate.pepper", "");
        final String environmentPepper = System.getenv().getOrDefault("CIPHERGATE_PEPPER", "");
        final String configuredPepper = config.getString("security.pepper", "");
        final String pepper = !propertyPepper.isBlank() ? propertyPepper
                : (!environmentPepper.isBlank() ? environmentPepper : configuredPepper);

        final int minimumLength = between(config.getInt("passwords.minimum-length", 10), 8, 128);
        final int maximumLength = between(config.getInt("passwords.maximum-length", 128), minimumLength, 256);

        return new SecuritySettings(
                config.getBoolean("authentication.allow-registration", true),
                between(config.getInt("authentication.timeout-seconds", 90), 15, 600),
                between(config.getInt("authentication.max-failed-attempts", 5), 3, 20),
                between(config.getInt("authentication.lockout-minutes", 10), 1, 1440),
                minimumLength,
                maximumLength,
                config.getBoolean("passwords.require-uppercase", true),
                config.getBoolean("passwords.require-lowercase", true),
                config.getBoolean("passwords.require-digit", true),
                config.getBoolean("passwords.require-symbol", false),
                between(config.getInt("passwords.pbkdf2-iterations", 310_000), 100_000, 2_000_000),
                between(config.getInt("passwords.salt-bytes", 24), 16, 64),
                between(config.getInt("passwords.hash-bits", 512), 256, 1024),
                pepper == null ? "" : pepper,
                config.getBoolean("security.block-chat-before-login", true),
                config.getBoolean("security.show-gate-on-join", true),
                config.getString("messages.generic-login-failure", "&cAuthentication failed. Check your credentials and try again.")
        );
    }

    private static int between(final int value, final int minimum, final int maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }
}
