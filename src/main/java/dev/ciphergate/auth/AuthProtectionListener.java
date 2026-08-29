package dev.ciphergate.auth;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.entity.ProjectileLaunchEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.inventory.PrepareAnvilEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerBedEnterEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemHeldEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Locale;

/** Enforces the pre-authentication sandbox without modifying a player's inventory or location. */
public final class AuthProtectionListener implements Listener {
    private final JavaPlugin plugin;
    private final SessionGuard sessions;
    private final GateMenu gate;

    public AuthProtectionListener(final JavaPlugin plugin, final SessionGuard sessions, final GateMenu gate) {
        this.plugin = plugin;
        this.sessions = sessions;
        this.gate = gate;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(final PlayerJoinEvent event) {
        final Player player = event.getPlayer();
        sessions.begin(player);
        if (sessions.isPending(player.getUniqueId()) && plugin.getConfig().getBoolean("security.show-gate-on-join", true)) {
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                if (player.isOnline() && sessions.isPending(player.getUniqueId())) {
                    gate.open(player);
                }
            });
        }
    }

    @EventHandler
    public void onQuit(final PlayerQuitEvent event) {
        gate.forget(event.getPlayer().getUniqueId());
        sessions.end(event.getPlayer().getUniqueId());
    }

    @EventHandler(ignoreCancelled = true)
    public void onMove(final PlayerMoveEvent event) {
        if (!pending(event.getPlayer()) || event instanceof PlayerTeleportEvent) {
            return;
        }
        final Location from = event.getFrom();
        final Location to = event.getTo();
        if (to != null && (from.getBlockX() != to.getBlockX() || from.getBlockY() != to.getBlockY()
                || from.getBlockZ() != to.getBlockZ())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onCommand(final PlayerCommandPreprocessEvent event) {
        final Player player = event.getPlayer();
        if (!pending(player)) {
            return;
        }
        final String message = event.getMessage().substring(1);
        final int space = message.indexOf(' ');
        final String root = (space == -1 ? message : message.substring(0, space)).toLowerCase(Locale.ROOT);
        if (root.equals("login") || root.equals("l") || root.equals("register") || root.equals("reg")
                || root.equals("changepassword") || root.equals("changepass") || root.equals("cpass")
                || root.equals("gate") || root.equals("cg") || root.equals("ciphergate") || root.equals("cga")) {
            return;
        }
        event.setCancelled(true);
        player.sendMessage(Component.text("Authenticate before using server commands.", NamedTextColor.RED));
    }

    @EventHandler(ignoreCancelled = true)
    public void onChat(final AsyncPlayerChatEvent event) {
        if (pending(event.getPlayer()) && plugin.getConfig().getBoolean("security.block-chat-before-login", true)) {
            event.setCancelled(true);
            plugin.getServer().getScheduler().runTask(plugin, () -> {
                if (event.getPlayer().isOnline() && pending(event.getPlayer())) {
                    event.getPlayer().sendMessage(Component.text("Chat is locked until you authenticate.", NamedTextColor.RED));
                }
            });
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteract(final PlayerInteractEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onInteractEntity(final PlayerInteractEntityEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onBreak(final BlockBreakEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlace(final BlockPlaceEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onDrop(final PlayerDropItemEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onHeldItem(final PlayerItemHeldEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onSwapHand(final PlayerSwapHandItemsEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onBed(final PlayerBedEnterEvent event) {
        cancelIfPending(event.getPlayer(), event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamage(final EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onAttack(final EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        } else if (event.getDamager() instanceof Projectile projectile && projectile.getShooter() instanceof Player player
                && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onPickup(final EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onFood(final FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onProjectile(final ProjectileLaunchEvent event) {
        if (event.getEntity().getShooter() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryOpen(final InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player && pending(player) && !gate.handles(event.getInventory())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryClick(final InventoryClickEvent event) {
        if (gate.handles(event.getView().getTopInventory())) {
            gate.click(event);
        } else if (event.getWhoClicked() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryDrag(final InventoryDragEvent event) {
        if (gate.handles(event.getView().getTopInventory())) {
            gate.drag(event);
        } else if (event.getWhoClicked() instanceof Player player && pending(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryClose(final InventoryCloseEvent event) {
        gate.close(event);
    }

    @EventHandler
    public void onPrepareAnvil(final PrepareAnvilEvent event) {
        gate.prepareAnvil(event);
    }

    private boolean pending(final Player player) {
        return sessions.isPending(player.getUniqueId());
    }

    private void cancelIfPending(final Player player, final org.bukkit.event.Cancellable event) {
        if (pending(player)) {
            event.setCancelled(true);
        }
    }
}
