package dev.ciphergate.auth;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Owns authentication state and makes async password results safe to apply. */
public final class SessionGuard {
    private final JavaPlugin plugin;
    private final AccountStore accounts;
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    private volatile SecuritySettings settings;

    public SessionGuard(final JavaPlugin plugin, final AccountStore accounts, final SecuritySettings settings) {
        this.plugin = plugin;
        this.accounts = accounts;
        this.settings = settings;
    }

    public void setSettings(final SecuritySettings settings) {
        this.settings = settings;
    }

    public void begin(final Player player) {
        final long now = System.currentTimeMillis();
        final Account account = accounts.find(player.getUniqueId());
        if (account != null && account.isLocked(now)) {
            player.kick(Component.text("CipherGate: this account is temporarily locked. Try again in "
                    + minutesRemaining(account.lockedUntil(), now) + ".", NamedTextColor.RED));
            return;
        }
        if (account == null && !settings.allowRegistration()) {
            player.kick(Component.text("CipherGate: registration is currently closed.", NamedTextColor.RED));
            return;
        }

        final Phase phase = account == null ? Phase.AWAITING_REGISTRATION : Phase.AWAITING_LOGIN;
        sessions.put(player.getUniqueId(), new Session(phase, now + settings.timeoutSeconds() * 1_000L));
        if (phase == Phase.AWAITING_LOGIN) {
            loginPrompt(player);
        } else {
            registrationPrompt(player);
        }
    }

    public void end(final UUID uuid) {
        sessions.remove(uuid);
    }

    public boolean isAuthenticated(final UUID uuid) {
        final Session session = sessions.get(uuid);
        return session != null && session.phase == Phase.AUTHENTICATED;
    }

    public boolean isPending(final UUID uuid) {
        final Session session = sessions.get(uuid);
        return session != null && session.phase != Phase.AUTHENTICATED;
    }

    public Phase phase(final UUID uuid) {
        final Session session = sessions.get(uuid);
        return session == null ? null : session.phase;
    }

    public Ticket beginVerification(final UUID uuid, final Phase expected) {
        final Session session = sessions.get(uuid);
        if (session == null || session.phase != expected) {
            return null;
        }
        session.phase = Phase.VERIFYING;
        session.ticket++;
        return new Ticket(uuid, session.ticket);
    }

    public void releaseVerification(final Ticket ticket) {
        final Session session = sessions.get(ticket.uuid());
        if (session == null || session.ticket != ticket.value() || session.phase != Phase.VERIFYING) {
            return;
        }
        session.phase = accounts.contains(ticket.uuid()) ? Phase.AWAITING_LOGIN : Phase.AWAITING_REGISTRATION;
    }

    public void authenticationSucceeded(final Ticket ticket, final boolean newlyRegistered) {
        final Session session = sessions.get(ticket.uuid());
        if (session == null || session.ticket != ticket.value() || session.phase != Phase.VERIFYING) {
            return;
        }
        session.phase = Phase.AUTHENTICATED;
        final Player player = Bukkit.getPlayer(ticket.uuid());
        if (player == null || !player.isOnline()) {
            return;
        }
        player.showTitle(Title.title(
                Component.text("GATE OPEN", NamedTextColor.AQUA),
                Component.text(newlyRegistered ? "Identity secured. Welcome in." : "Identity verified. Welcome back.",
                        NamedTextColor.GRAY),
                Title.Times.times(Duration.ofMillis(250), Duration.ofMillis(1_750), Duration.ofMillis(500))
        ));
        player.sendMessage(Component.text("◆ ", NamedTextColor.DARK_AQUA)
                .append(Component.text("CipherGate accepted your identity.", NamedTextColor.GREEN)));
    }

    /** Marks a player as verified after the old password was confirmed and replaced. */
    public void passwordChanged(final UUID uuid) {
        final Session session = sessions.get(uuid);
        if (session == null) {
            return;
        }
        session.phase = Phase.AUTHENTICATED;
        final Player player = Bukkit.getPlayer(uuid);
        if (player == null || !player.isOnline()) {
            return;
        }
        player.showTitle(Title.title(
                Component.text("PASSWORD UPDATED", NamedTextColor.AQUA),
                Component.text("Your identity is secured with the new password.", NamedTextColor.GRAY),
                Title.Times.times(Duration.ofMillis(250), Duration.ofMillis(1_750), Duration.ofMillis(500))
        ));
        player.sendMessage(Component.text("◆ ", NamedTextColor.DARK_AQUA)
                .append(Component.text("Password changed successfully.", NamedTextColor.GREEN)));
    }

    public void authenticationFailed(final Ticket ticket, final Failure failure) {
        final Session session = sessions.get(ticket.uuid());
        if (session == null || session.ticket != ticket.value() || session.phase != Phase.VERIFYING) {
            return;
        }
        final Player player = Bukkit.getPlayer(ticket.uuid());
        if (failure == Failure.LOCKED) {
            sessions.remove(ticket.uuid());
            if (player != null) {
                player.kick(Component.text("CipherGate: too many failed attempts. Your account is temporarily locked.",
                        NamedTextColor.RED));
            }
            return;
        }
        session.phase = accounts.contains(ticket.uuid()) ? Phase.AWAITING_LOGIN : Phase.AWAITING_REGISTRATION;
        if (player == null) {
            return;
        }
        if (failure == Failure.NOT_REGISTERED) {
            registrationPrompt(player);
        } else if (failure == Failure.ALREADY_REGISTERED) {
            loginPrompt(player);
        } else if (failure == Failure.ERROR) {
            player.sendMessage(Component.text("CipherGate could not complete that request. Please try again.",
                    NamedTextColor.RED));
        } else {
            player.sendMessage(Component.text("Authentication failed. Check your credentials and try again.",
                    NamedTextColor.RED));
            loginPrompt(player);
        }
    }

    public void tick() {
        final long now = System.currentTimeMillis();
        for (final Map.Entry<UUID, Session> entry : sessions.entrySet()) {
            final Session session = entry.getValue();
            if (session.phase == Phase.AUTHENTICATED) {
                continue;
            }
            final Player player = Bukkit.getPlayer(entry.getKey());
            if (player == null || !player.isOnline()) {
                sessions.remove(entry.getKey(), session);
                continue;
            }
            if (now >= session.deadline) {
                sessions.remove(entry.getKey(), session);
                player.kick(Component.text("CipherGate: authentication timed out.", NamedTextColor.RED));
                continue;
            }
            final long seconds = Math.max(1, (session.deadline - now + 999) / 1_000);
            final String action = session.phase == Phase.AWAITING_REGISTRATION ? "Register" : "Authenticate";
            player.sendActionBar(Component.text("◆ " + action + " to open the gate • " + seconds + "s",
                    NamedTextColor.AQUA));
        }
    }

    public void loginPrompt(final Player player) {
        player.sendMessage(Component.text("◆ CIPHER GATE ", NamedTextColor.AQUA)
                .append(Component.text("Use ", NamedTextColor.GRAY))
                .append(Component.text("/login <password>", NamedTextColor.WHITE))
                .append(Component.text(" to authenticate.", NamedTextColor.GRAY)));
    }

    public void registrationPrompt(final Player player) {
        player.sendMessage(Component.text("◆ CIPHER GATE ", NamedTextColor.AQUA)
                .append(Component.text("Create your identity with ", NamedTextColor.GRAY))
                .append(Component.text("/register <password> <confirm>", NamedTextColor.WHITE))
                .append(Component.text(".", NamedTextColor.GRAY)));
    }

    public enum Phase {
        AWAITING_LOGIN,
        AWAITING_REGISTRATION,
        VERIFYING,
        AUTHENTICATED
    }

    public enum Failure {
        INVALID,
        LOCKED,
        NOT_REGISTERED,
        ALREADY_REGISTERED,
        ERROR
    }

    public record Ticket(UUID uuid, long value) {
    }

    private static final class Session {
        private volatile Phase phase;
        private final long deadline;
        private long ticket;

        private Session(final Phase phase, final long deadline) {
            this.phase = phase;
            this.deadline = deadline;
        }
    }

    private static String minutesRemaining(final long lockedUntil, final long now) {
        final long seconds = Math.max(1, (lockedUntil - now + 999) / 1_000);
        return Duration.ofSeconds(seconds).toMinutes() + 1 + " minute(s)";
    }
}
