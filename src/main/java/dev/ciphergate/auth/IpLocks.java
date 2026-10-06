package dev.ciphergate.auth;

import org.bukkit.entity.Player;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Normalizes and compares IP addresses for the optional per-account IP lock.
 * Only literal IPv4/IPv6 addresses are accepted; hostnames are rejected so a
 * lock can never depend on (or trigger) a DNS lookup.
 */
public final class IpLocks {
    private IpLocks() {
    }

    /** Returns the player's current address, or an empty string when unavailable. */
    public static String currentIp(final Player player) {
        if (player.getAddress() == null || player.getAddress().getAddress() == null) {
            return "";
        }
        return player.getAddress().getAddress().getHostAddress();
    }

    /**
     * Normalizes a user-supplied address to its canonical text form.
     * Returns null when the value is not a valid literal IP address.
     */
    public static String normalize(final String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        final String trimmed = value.trim();
        if (!looksLikeLiteral(trimmed)) {
            return null;
        }
        try {
            return InetAddress.getByName(trimmed).getHostAddress();
        } catch (final UnknownHostException | SecurityException exception) {
            return null;
        }
    }

    /**
     * Compares a stored lock against a current address. Both sides are parsed
     * so equivalent forms (for example compressed vs. expanded IPv6) match.
     */
    public static boolean matches(final String lockedIp, final String currentIp) {
        if (lockedIp == null || lockedIp.isBlank() || currentIp == null || currentIp.isBlank()) {
            return false;
        }
        if (lockedIp.equalsIgnoreCase(currentIp)) {
            return true;
        }
        try {
            final InetAddress locked = InetAddress.getByName(lockedIp.trim());
            final InetAddress current = InetAddress.getByName(currentIp.trim());
            return locked.equals(current);
        } catch (final UnknownHostException | SecurityException exception) {
            return false;
        }
    }

    /**
     * Accepts only characters that can appear in a numeric address. This keeps
     * hostnames out before getByName gets a chance to resolve anything.
     */
    private static boolean looksLikeLiteral(final String value) {
        if (value.indexOf(':') >= 0) {
            // Possible IPv6 literal: hex digits, colons, dots (embedded IPv4),
            // and an optional %zone id.
            for (int index = 0; index < value.length(); index++) {
                final char current = value.charAt(index);
                final boolean hex = (current >= '0' && current <= '9')
                        || (current >= 'a' && current <= 'f')
                        || (current >= 'A' && current <= 'F');
                if (!hex && current != ':' && current != '.' && current != '%') {
                    return false;
                }
            }
            return true;
        }
        // Possible IPv4 literal: digits and dots only.
        for (int index = 0; index < value.length(); index++) {
            final char current = value.charAt(index);
            if (!Character.isDigit(current) && current != '.') {
                return false;
            }
        }
        return true;
    }
}
