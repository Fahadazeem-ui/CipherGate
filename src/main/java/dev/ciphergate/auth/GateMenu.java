package dev.ciphergate.auth;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.PrepareAnvilEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.inventory.view.AnvilView;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The optional Cipher Gate entry point. It uses an anvil text field, so a
 * password is not sent as a chat message. Password input is never put in an
 * item's display name by this plugin and the temporary inventory is cleared.
 */
public final class GateMenu {
    private static final int LOGIN_SLOT = 11;
    private static final int STATUS_SLOT = 13;
    private static final int REGISTER_SLOT = 15;

    private final JavaPlugin plugin;
    private final SessionGuard sessions;
    private final AuthenticationService authentication;
    private final Map<UUID, Flow> flows = new ConcurrentHashMap<>();
    private volatile SecuritySettings settings;

    public GateMenu(
            final JavaPlugin plugin,
            final SessionGuard sessions,
            final AuthenticationService authentication,
            final SecuritySettings settings
    ) {
        this.plugin = plugin;
        this.sessions = sessions;
        this.authentication = authentication;
        this.settings = settings;
    }

    public void setSettings(final SecuritySettings settings) {
        this.settings = settings;
    }

    public void open(final Player player) {
        if (!sessions.isPending(player.getUniqueId())) {
            player.sendMessage(Component.text("Your CipherGate session is already open.", NamedTextColor.GREEN));
            return;
        }
        final SessionGuard.Phase phase = sessions.phase(player.getUniqueId());
        if (phase == SessionGuard.Phase.VERIFYING) {
            player.sendMessage(Component.text("CipherGate is checking your last request.", NamedTextColor.GRAY));
            return;
        }
        final Flow flow = flows.computeIfAbsent(player.getUniqueId(), ignored -> new Flow());
        openMenu(player, flow);
    }

    public void forget(final UUID uuid) {
        final Flow flow = flows.remove(uuid);
        if (flow != null) {
            flow.clear();
        }
    }

    public boolean handles(final Inventory inventory) {
        return inventory.getHolder() instanceof GateHolder;
    }

    public void click(final InventoryClickEvent event) {
        final Player player = (Player) event.getWhoClicked();
        final Inventory top = event.getView().getTopInventory();
        if (!(top.getHolder() instanceof GateHolder holder)) {
            return;
        }
        event.setCancelled(true);
        if (event.getRawSlot() < 0 || event.getRawSlot() >= top.getSize()) {
            return;
        }
        final Flow flow = flows.get(player.getUniqueId());
        if (flow == null || flow.holder != holder) {
            return;
        }
        if (holder.screen == Screen.MENU) {
            if (event.getRawSlot() == LOGIN_SLOT) {
                if (sessions.phase(player.getUniqueId()) == SessionGuard.Phase.AWAITING_LOGIN) {
                    openPasswordEntry(player, flow, Screen.LOGIN_ENTRY);
                } else {
                    sessions.registrationPrompt(player);
                }
            } else if (event.getRawSlot() == REGISTER_SLOT) {
                if (sessions.phase(player.getUniqueId()) == SessionGuard.Phase.AWAITING_REGISTRATION) {
                    openPasswordEntry(player, flow, Screen.REGISTER_ENTRY);
                } else {
                    sessions.loginPrompt(player);
                }
            } else if (event.getRawSlot() == STATUS_SLOT) {
                player.sendMessage(Component.text("CipherGate security: PBKDF2-SHA512 • "
                        + settings.pbkdf2Iterations() + " iterations • "
                        + settings.maxFailedAttempts() + " attempts before lockout.", NamedTextColor.AQUA));
            }
            return;
        }
        if (event.getRawSlot() != 2 || !(event.getView() instanceof AnvilView anvilView)) {
            return;
        }

        final String typed = anvilView.getRenameText();
        final char[] password = typed == null ? new char[0] : typed.toCharArray();
        clearInventory(top);
        if (password.length == 0) {
            Arrays.fill(password, '\0');
            player.sendMessage(Component.text("Enter a password in the rename field first.", NamedTextColor.RED));
            return;
        }
        submitPassword(player, flow, holder.screen, password);
    }

    public void drag(final InventoryDragEvent event) {
        if (handles(event.getView().getTopInventory())) {
            event.setCancelled(true);
        }
    }

    public void prepareAnvil(final PrepareAnvilEvent event) {
        if (!(event.getInventory().getHolder() instanceof GateHolder holder) || !holder.screen.isEntry()) {
            return;
        }
        final String entered = event.getView().getRenameText();
        if (entered == null || entered.isEmpty()) {
            event.setResult(null);
            return;
        }
        event.setResult(item(Material.LIME_DYE, "VERIFY & UNLOCK", NamedTextColor.GREEN,
                "Click to submit. The entry is cleared immediately."));
    }

    public void close(final InventoryCloseEvent event) {
        final Inventory inventory = event.getInventory();
        if (!(inventory.getHolder() instanceof GateHolder holder)) {
            return;
        }
        clearInventory(inventory);
        final UUID uuid = event.getPlayer().getUniqueId();
        final Flow flow = flows.get(uuid);
        // A screen swap changes flow.holder before Bukkit fires the previous close event.
        if (flow != null && flow.holder == holder) {
            forget(uuid);
        }
    }

    private void submitPassword(final Player player, final Flow flow, final Screen screen, final char[] password) {
        if (screen == Screen.LOGIN_ENTRY) {
            finishFlow(player.getUniqueId(), flow);
            player.closeInventory();
            authentication.login(player, password);
            return;
        }
        if (screen == Screen.REGISTER_ENTRY) {
            final String violation = PasswordPolicy.violation(password, settings);
            if (violation != null) {
                Arrays.fill(password, '\0');
                player.sendMessage(Component.text(violation, NamedTextColor.RED));
                openMenu(player, flow);
                return;
            }
            flow.registrationDraft = password;
            openPasswordEntry(player, flow, Screen.CONFIRM_ENTRY);
            player.sendMessage(Component.text("Confirm the same password to seal your identity.", NamedTextColor.GRAY));
            return;
        }
        if (screen == Screen.CONFIRM_ENTRY) {
            final char[] first = flow.registrationDraft;
            flow.registrationDraft = null;
            if (first == null || !constantTimeEquals(first, password)) {
                if (first != null) {
                    Arrays.fill(first, '\0');
                }
                Arrays.fill(password, '\0');
                player.sendMessage(Component.text("Passwords did not match. Start again.", NamedTextColor.RED));
                openMenu(player, flow);
                return;
            }
            Arrays.fill(first, '\0');
            finishFlow(player.getUniqueId(), flow);
            player.closeInventory();
            authentication.register(player, password);
        }
    }

    private void openMenu(final Player player, final Flow flow) {
        final GateHolder holder = new GateHolder(Screen.MENU);
        final Inventory inventory = Bukkit.createInventory(holder, 27,
                Component.text("◆ Cipher Gate", NamedTextColor.DARK_AQUA));
        holder.attach(inventory);
        fillFrame(inventory);
        inventory.setItem(LOGIN_SLOT, item(Material.TRIPWIRE_HOOK, "UNLOCK IDENTITY", NamedTextColor.AQUA,
                "Enter through the secure login gate."));
        inventory.setItem(STATUS_SLOT, item(Material.SHIELD, "SECURITY STATUS", NamedTextColor.YELLOW,
                "Strong hashes • lockouts • protected session."));
        inventory.setItem(REGISTER_SLOT, item(Material.AMETHYST_SHARD, "CREATE IDENTITY", NamedTextColor.LIGHT_PURPLE,
                "Register with a secure password."));
        show(player, flow, holder);
    }

    private void openPasswordEntry(final Player player, final Flow flow, final Screen screen) {
        final GateHolder holder = new GateHolder(screen);
        final String label = screen == Screen.LOGIN_ENTRY ? "Login"
                : (screen == Screen.CONFIRM_ENTRY ? "Confirm" : "Register");
        final Inventory inventory = Bukkit.createInventory(holder, org.bukkit.event.inventory.InventoryType.ANVIL,
                Component.text("Cipher Gate • " + label, NamedTextColor.DARK_AQUA));
        holder.attach(inventory);
        final ItemStack entryToken = new ItemStack(Material.PAPER);
        final ItemMeta entryMeta = entryToken.getItemMeta();
        entryMeta.displayName(Component.empty());
        entryToken.setItemMeta(entryMeta);
        inventory.setItem(0, entryToken);
        show(player, flow, holder);
        player.sendMessage(Component.text("Type your password in the anvil rename field, then click VERIFY & UNLOCK.",
                NamedTextColor.GRAY));
    }

    private void show(final Player player, final Flow flow, final GateHolder next) {
        final GateHolder old = flow.holder;
        flow.holder = next;
        if (old != null && old.inventory != null) {
            clearInventory(old.inventory);
        }
        player.openInventory(next.inventory);
    }

    private void finishFlow(final UUID uuid, final Flow flow) {
        flows.remove(uuid, flow);
        flow.clear();
    }

    private static boolean constantTimeEquals(final char[] first, final char[] second) {
        int difference = first.length ^ second.length;
        final int length = Math.max(first.length, second.length);
        for (int index = 0; index < length; index++) {
            final char left = index < first.length ? first[index] : 0;
            final char right = index < second.length ? second[index] : 0;
            difference |= left ^ right;
        }
        return difference == 0;
    }

    private static void fillFrame(final Inventory inventory) {
        final ItemStack pane = item(Material.GRAY_STAINED_GLASS_PANE, " ", NamedTextColor.GRAY);
        for (int slot = 0; slot < inventory.getSize(); slot++) {
            if (slot < 9 || slot >= 18 || slot % 9 == 0 || slot % 9 == 8) {
                inventory.setItem(slot, pane);
            }
        }
    }

    private static ItemStack item(final Material material, final String title, final NamedTextColor color, final String... lines) {
        final ItemStack result = new ItemStack(material);
        final ItemMeta meta = result.getItemMeta();
        meta.displayName(Component.text(title, color));
        final List<Component> lore = new ArrayList<>();
        for (final String line : lines) {
            lore.add(Component.text(line, NamedTextColor.GRAY));
        }
        meta.lore(lore);
        result.setItemMeta(meta);
        return result;
    }

    private static void clearInventory(final Inventory inventory) {
        inventory.clear();
    }

    private enum Screen {
        MENU,
        LOGIN_ENTRY,
        REGISTER_ENTRY,
        CONFIRM_ENTRY;

        private boolean isEntry() {
            return this != MENU;
        }
    }

    private static final class Flow {
        private GateHolder holder;
        private char[] registrationDraft;

        private void clear() {
            if (registrationDraft != null) {
                Arrays.fill(registrationDraft, '\0');
                registrationDraft = null;
            }
            if (holder != null && holder.inventory != null) {
                clearInventory(holder.inventory);
            }
        }
    }

    private static final class GateHolder implements InventoryHolder {
        private final Screen screen;
        private Inventory inventory;

        private GateHolder(final Screen screen) {
            this.screen = screen;
        }

        private void attach(final Inventory inventory) {
            this.inventory = inventory;
        }

        @Override
        public Inventory getInventory() {
            return inventory;
        }
    }
}
