package dev.ciphergate.auth;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Performs deliberately expensive password work off the server thread. The
 * SessionGuard ticket prevents a late task from authenticating a reconnected player.
 */
public final class AuthenticationService {
    private final JavaPlugin plugin;
    private final AccountStore accounts;
    private final SessionGuard sessions;
    private final PasswordHasher hasher;
    private volatile SecuritySettings settings;

    public AuthenticationService(
            final JavaPlugin plugin,
            final AccountStore accounts,
            final SessionGuard sessions,
            final PasswordHasher hasher,
            final SecuritySettings settings
    ) {
        this.plugin = plugin;
        this.accounts = accounts;
        this.sessions = sessions;
        this.hasher = hasher;
        this.settings = settings;
    }

    public void setSettings(final SecuritySettings settings) {
        this.settings = settings;
        hasher.setSettings(settings);
    }

    /** Takes ownership of password and clears it after the asynchronous operation. */
    public void login(final Player player, final char[] password) {
        final SessionGuard.Ticket ticket = sessions.beginVerification(player.getUniqueId(), SessionGuard.Phase.AWAITING_LOGIN);
        if (ticket == null) {
            Arrays.fill(password, '\0');
            player.sendMessage(net.kyori.adventure.text.Component.text("You are not ready to log in right now."));
            return;
        }
        authenticateAsync(ticket, password);
    }

    /** Takes ownership of password and clears it after the asynchronous operation. */
    public void register(final Player player, final char[] password) {
        final SessionGuard.Ticket ticket = sessions.beginVerification(player.getUniqueId(), SessionGuard.Phase.AWAITING_REGISTRATION);
        if (ticket == null) {
            Arrays.fill(password, '\0');
            player.sendMessage(net.kyori.adventure.text.Component.text("You are not ready to register right now."));
            return;
        }
        registerAsync(ticket, password);
    }

    /**
     * Confirms the existing password before a change is allowed. Failed checks
     * count toward the same persistent lockout policy as ordinary login attempts.
     */
    public void verifyCurrentPassword(
            final Player player,
            final char[] password,
            final Consumer<PasswordCheck> completion
    ) {
        final UUID uuid = player.getUniqueId();
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            PasswordCheck outcome = PasswordCheck.INVALID;
            try {
                final long now = System.currentTimeMillis();
                final Account account = accounts.find(uuid);
                if (account == null) {
                    outcome = PasswordCheck.ERROR;
                } else if (account.isLocked(now)) {
                    outcome = PasswordCheck.LOCKED;
                } else if (hasher.verify(password, account.passwordHash()).valid()) {
                    outcome = PasswordCheck.VERIFIED;
                } else {
                    final Account updated = accounts.recordFailure(uuid, now, settings);
                    outcome = updated != null && updated.isLocked(now) ? PasswordCheck.LOCKED : PasswordCheck.INVALID;
                }
            } catch (final GeneralSecurityException exception) {
                plugin.getLogger().warning("CipherGate could not verify the current password: "
                        + exception.getClass().getSimpleName());
                outcome = PasswordCheck.ERROR;
            } finally {
                Arrays.fill(password, '\0');
            }
            final PasswordCheck result = outcome;
            Bukkit.getScheduler().runTask(plugin, () -> completion.accept(result));
        });
    }

    /** Replaces a password after GateMenu has verified the current password. */
    public void changePassword(
            final Player player,
            final char[] password,
            final Consumer<PasswordUpdate> completion
    ) {
        final UUID uuid = player.getUniqueId();
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            PasswordUpdate outcome = PasswordUpdate.ERROR;
            try {
                final Account account = accounts.find(uuid);
                final long now = System.currentTimeMillis();
                if (account == null) {
                    outcome = PasswordUpdate.ERROR;
                } else if (account.isLocked(now)) {
                    outcome = PasswordUpdate.LOCKED;
                } else {
                    final String replacement = hasher.hash(password);
                    accounts.recordSuccess(uuid, replacement, now);
                    outcome = PasswordUpdate.UPDATED;
                }
            } catch (final GeneralSecurityException exception) {
                plugin.getLogger().warning("CipherGate could not update a password: "
                        + exception.getClass().getSimpleName());
            } finally {
                Arrays.fill(password, '\0');
            }
            final PasswordUpdate result = outcome;
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (result == PasswordUpdate.UPDATED) {
                    sessions.passwordChanged(uuid);
                }
                completion.accept(result);
            });
        });
    }

    private void authenticateAsync(final SessionGuard.Ticket ticket, final char[] password) {
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            SessionGuard.Failure outcome = SessionGuard.Failure.INVALID;
            try {
                final UUID uuid = ticket.uuid();
                final long now = System.currentTimeMillis();
                final Account account = accounts.find(uuid);
                if (account == null) {
                    outcome = SessionGuard.Failure.NOT_REGISTERED;
                } else if (account.isLocked(now)) {
                    outcome = SessionGuard.Failure.LOCKED;
                } else {
                    final PasswordHasher.Verification verification = hasher.verify(password, account.passwordHash());
                    if (!verification.valid()) {
                        final Account updated = accounts.recordFailure(uuid, now, settings);
                        outcome = updated != null && updated.isLocked(now)
                                ? SessionGuard.Failure.LOCKED
                                : SessionGuard.Failure.INVALID;
                    } else {
                        final String replacement = verification.needsUpgrade() ? hasher.hash(password) : null;
                        accounts.recordSuccess(uuid, replacement, now);
                        outcome = null;
                    }
                }
            } catch (final GeneralSecurityException exception) {
                plugin.getLogger().warning("CipherGate could not verify a password: " + exception.getClass().getSimpleName());
                outcome = SessionGuard.Failure.ERROR;
            } finally {
                Arrays.fill(password, '\0');
            }
            final SessionGuard.Failure result = outcome;
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (result == null) {
                    sessions.authenticationSucceeded(ticket, false);
                } else {
                    sessions.authenticationFailed(ticket, result);
                }
            });
        });
    }

    private void registerAsync(final SessionGuard.Ticket ticket, final char[] password) {
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            SessionGuard.Failure outcome = null;
            try {
                if (accounts.contains(ticket.uuid())) {
                    outcome = SessionGuard.Failure.ALREADY_REGISTERED;
                } else {
                    final String hash = hasher.hash(password);
                    if (!accounts.create(ticket.uuid(), hash, System.currentTimeMillis())) {
                        outcome = SessionGuard.Failure.ALREADY_REGISTERED;
                    }
                }
            } catch (final GeneralSecurityException exception) {
                plugin.getLogger().warning("CipherGate could not create a password hash: " + exception.getClass().getSimpleName());
                outcome = SessionGuard.Failure.ERROR;
            } finally {
                Arrays.fill(password, '\0');
            }
            final SessionGuard.Failure result = outcome;
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (result == null) {
                    sessions.authenticationSucceeded(ticket, true);
                } else {
                    sessions.authenticationFailed(ticket, result);
                }
            });
        });
    }

    public enum PasswordCheck {
        VERIFIED,
        INVALID,
        LOCKED,
        ERROR
    }

    public enum PasswordUpdate {
        UPDATED,
        LOCKED,
        ERROR
    }
}
