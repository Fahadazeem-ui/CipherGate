package dev.ciphergate.auth;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.entity.Player;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.PrepareAnvilEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.UUID;

/**
 * Compatibility command guide retained for players who use /gate. The former
 * anvil UI was intentionally removed: vanilla anvils can charge XP and behave
 * differently between Java and Bedrock clients.
 */
public final class GateMenu {
    private final SessionGuard sessions;

    public GateMenu(
            final JavaPlugin plugin,
            final SessionGuard sessions,
            final AuthenticationService authentication,
            final SecuritySettings settings
    ) {
        this.sessions = sessions;
    }

    public void setSettings(final SecuritySettings settings) {
        // Kept so configuration reload remains source-compatible.
    }

    public void open(final Player player) {
        final SessionGuard.Phase phase = sessions.phase(player.getUniqueId());
        if (phase == null) {
            player.sendMessage(Component.text("CipherGate has not started an authentication session for you.",
                    NamedTextColor.RED));
            return;
        }
        if (phase == SessionGuard.Phase.AWAITING_REGISTRATION) {
            player.sendMessage(Component.text("Register with: ", NamedTextColor.AQUA)
                    .append(Component.text("/register <password> <confirm>", NamedTextColor.WHITE)));
        } else if (phase == SessionGuard.Phase.AWAITING_LOGIN) {
            player.sendMessage(Component.text("Log in with: ", NamedTextColor.AQUA)
                    .append(Component.text("/login <password>", NamedTextColor.WHITE)));
        } else if (phase == SessionGuard.Phase.AUTHENTICATED) {
            player.sendMessage(Component.text("Change password with: ", NamedTextColor.AQUA)
                    .append(Component.text("/changepassword <old> <new> <confirm>", NamedTextColor.WHITE)));
        } else {
            player.sendMessage(Component.text("CipherGate is checking your last request.", NamedTextColor.GRAY));
        }
    }

    public void forget(final UUID uuid) {
        // No temporary inventory/password state exists.
    }

    public boolean handles(final Inventory inventory) {
        return false;
    }

    public void click(final InventoryClickEvent event) {
        // No custom inventory exists.
    }

    public void drag(final InventoryDragEvent event) {
        // No custom inventory exists.
    }

    public void prepareAnvil(final PrepareAnvilEvent event) {
        // CipherGate never opens or changes anvils.
    }

    public void close(final InventoryCloseEvent event) {
        // CipherGate never opens or changes anvils.
    }
}
