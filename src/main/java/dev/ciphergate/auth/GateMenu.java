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
 * A contained password-entry flow. The anvil result deliberately remains a
 * PAPER item because vanilla clients only allow a matching result to be taken.
 */
public final class GateMenu {
    private static final int LOGIN_SLOT = 11;
    private static final int STATUS_SLOT = 13;
    private static final int ACTION_SLOT = 15;

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
        this.sessions = sessions;
        this.authentication = authentication;
        this.settings = settings;
    }

    public void setSettings(final SecuritySettings settings) {
        this.settings = settings;
    }

    public void open(final Player player) {
        final SessionGuard.Phase phase = sessions.phase(player.getUniqueId());
        if (phase == null) {
            player.sendMessage(Component.text("CipherGate has not started an authentication session for you.",
                    NamedTextColor.RED));
            return;
        }
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
        if (!(event.getWhoClicked() instanceof Player player)) {
            event.setCancelled(true);
            return;
        }
        final Inventory top = event.getView().getTopInventory();
        if (!(top.getHolder() instanceof GateHolder holder)) {
            return;
        }
        event.setCancelled(true);
        if (event.getRawSlot() < 0 || event.getRawSlot() >= top.getSize()) {
            return;
        }
        final Flow flow = flows.get(player.getUniqueId());
        if (flow == null || flow.holder != holder || flow.waitingForCheck) {
            return;
        }
        if (holder.screen == Screen.MENU) {
            clickMenu(player, flow, event.getRawSlot());
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
        final ItemStack input = event.getInventory().getItem(0);
        if (entered == null || entered.isEmpty() || input == null || input.getType().isAir()) {
            event.setResult(null);
            return;
        }

        // The output must match the input material or the client refuses to click it.
        final ItemStack result = input.clone();
        final ItemMeta meta = result.getItemMeta();
        meta.displayName(Component.text("CONTINUE", NamedTextColor.GREEN));
        meta.lore(List.of(Component.text("Click to submit. The entry is cleared immediately.", NamedTextColor.GRAY)));
        result.setItemMeta(meta);
        event.setResult(result);
    }

    public void close(final InventoryCloseEvent event) {
        final Inventory inventory = event.getInventory();
        if (!(inventory.getHolder() instanceof GateHolder holder)) {
            return;
        }
        clearInventory(inventory);
        final UUID uuid = event.getPlayer().getUniqueId();
        final Flow flow = flows.get(uuid);
        // An intentional screen swap changes holder before Bukkit closes the old screen.
        if (flow != null && flow.holder == holder && !flow.waitingForCheck) {
            forget(uuid);
        }
    }

    private void clickMenu(final Player player, final Flow flow, final int slot) {
        final SessionGuard.Phase phase = sessions.phase(player.getUniqueId());
        if (slot == LOGIN_SLOT) {
            if (phase == SessionGuard.Phase.AWAITING_LOGIN) {
                openPasswordEntry(player, flow, Screen.LOGIN_ENTRY);
            } else if (phase == SessionGuard.Phase.AWAITING_REGISTRATION) {
                player.sendMessage(Component.text("Register your identity first.", NamedTextColor.YELLOW));
            } else {
                player.sendMessage(Component.text("You are already logged in.", NamedTextColor.GREEN));
            }
            return;
        }
        if (slot == ACTION_SLOT) {
            if (phase == SessionGuard.Phase.AWAITING_REGISTRATION) {
                openPasswordEntry(player, flow, Screen.REGISTER_ENTRY);
            } else {
                openPasswordEntry(player, flow, Screen.CHANGE_CURRENT_ENTRY);
            }
            return;
        }
        if (slot == STATUS_SLOT) {
            player.sendMessage(Component.text("CipherGate security: PBKDF2-SHA512 • "
                    + settings.pbkdf2Iterations() + " iterations • "
                    + settings.maxFailedAttempts() + " attempts before lockout.", NamedTextColor.AQUA));
        }
    }

    private void submitPassword(final Player player, final Flow flow, final Screen screen, final char[] password) {
        switch (screen) {
            case LOGIN_ENTRY -> {
                finishFlow(player.getUniqueId(), flow);
                player.closeInventory();
                authentication.login(player, password);
            }
            case REGISTER_ENTRY -> beginRegistration(player, flow, password);
            case REGISTER_CONFIRM_ENTRY -> finishRegistration(player, flow, password);
            case CHANGE_CURRENT_ENTRY -> verifyCurrentPassword(player, flow, password);
            case CHANGE_NEW_ENTRY -> beginPasswordChange(player, flow, password);
            case CHANGE_CONFIRM_ENTRY -> finishPasswordChange(player, flow, password);
            case MENU -> Arrays.fill(password, '\0');
        }
    }

    private void beginRegistration(final Player player, final Flow flow, final char[] password) {
        final String violation = PasswordPolicy.violation(password, settings);
        if (violation != null) {
            Arrays.fill(password, '\0');
            player.sendMessage(Component.text(violation, NamedTextColor.RED));
            openMenu(player, flow);
            return;
        }
        flow.registrationDraft = password;
        openPasswordEntry(player, flow, Screen.REGISTER_CONFIRM_ENTRY);
        player.sendMessage(Component.text("Enter the same password again to confirm registration.", NamedTextColor.GRAY));
    }

    private void finishRegistration(final Player player, final Flow flow, final char[] confirmation) {
        final char[] first = flow.registrationDraft;
        flow.registrationDraft = null;
        if (first == null || !constantTimeEquals(first, confirmation)) {
            if (first != null) {
                Arrays.fill(first, '\0');
            }
            Arrays.fill(confirmation, '\0');
            player.sendMessage(Component.text("Passwords did not match. Start registration again.", NamedTextColor.RED));
            openMenu(player, flow);
            return;
        }
        Arrays.fill(first, '\0');
        finishFlow(player.getUniqueId(), flow);
        player.closeInventory();
        authentication.register(player, confirmation);
    }

    private void verifyCurrentPassword(final Player player, final Flow flow, final char[] password) {
        flow.waitingForCheck = true;
        player.closeInventory();
        authentication.verifyCurrentPassword(player, password, result -> {
            final Flow active = flows.get(player.getUniqueId());
            if (active != flow || !player.isOnline()) {
                return;
            }
            active.waitingForCheck = false;
            if (result == AuthenticationService.PasswordCheck.VERIFIED) {
                active.changeAuthorized = true;
                player.sendMessage(Component.text("Current password confirmed. Choose a new password.", NamedTextColor.GREEN));
                openPasswordEntry(player, active, Screen.CHANGE_NEW_ENTRY);
            } else if (result == AuthenticationService.PasswordCheck.LOCKED) {
                forget(player.getUniqueId());
                sessions.end(player.getUniqueId());
                player.kick(Component.text("CipherGate: too many failed attempts. Your account is temporarily locked.",
                        NamedTextColor.RED));
            } else {
                player.sendMessage(Component.text(result == AuthenticationService.PasswordCheck.ERROR
                        ? "CipherGate could not check that password. Try again."
                        : "Current password was incorrect.", NamedTextColor.RED));
                openMenu(player, active);
            }
        });
    }

    private void beginPasswordChange(final Player player, final Flow flow, final char[] password) {
        if (!flow.changeAuthorized) {
            Arrays.fill(password, '\0');
            player.sendMessage(Component.text("Confirm your current password before changing it.", NamedTextColor.RED));
            openMenu(player, flow);
            return;
        }
        final String violation = PasswordPolicy.violation(password, settings);
        if (violation != null) {
            Arrays.fill(password, '\0');
            player.sendMessage(Component.text(violation, NamedTextColor.RED));
            openPasswordEntry(player, flow, Screen.CHANGE_NEW_ENTRY);
            return;
        }
        flow.newPasswordDraft = password;
        openPasswordEntry(player, flow, Screen.CHANGE_CONFIRM_ENTRY);
        player.sendMessage(Component.text("Enter the new password again to confirm it.", NamedTextColor.GRAY));
    }

    private void finishPasswordChange(final Player player, final Flow flow, final char[] confirmation) {
        final char[] newPassword = flow.newPasswordDraft;
        flow.newPasswordDraft = null;
        flow.changeAuthorized = false;
        if (newPassword == null || !constantTimeEquals(newPassword, confirmation)) {
            if (newPassword != null) {
                Arrays.fill(newPassword, '\0');
            }
            Arrays.fill(confirmation, '\0');
            player.sendMessage(Component.text("New passwords did not match. Start again.", NamedTextColor.RED));
            openMenu(player, flow);
            return;
        }
        Arrays.fill(confirmation, '\0');
        finishFlow(player.getUniqueId(), flow);
        player.closeInventory();
        authentication.changePassword(player, newPassword, result -> {
            if (result == AuthenticationService.PasswordUpdate.UPDATED || !player.isOnline()) {
                return;
            }
            if (result == AuthenticationService.PasswordUpdate.LOCKED) {
                sessions.end(player.getUniqueId());
                player.kick(Component.text("CipherGate: your account is temporarily locked.", NamedTextColor.RED));
            } else {
                player.sendMessage(Component.text("CipherGate could not update your password. Try again.", NamedTextColor.RED));
            }
        });
    }

    private void openMenu(final Player player, final Flow flow) {
        final SessionGuard.Phase phase = sessions.phase(player.getUniqueId());
        final GateHolder holder = new GateHolder(Screen.MENU);
        final Inventory inventory = Bukkit.createInventory(holder, 27,
                Component.text("◆ Cipher Gate", NamedTextColor.DARK_AQUA));
        holder.attach(inventory);
        fillFrame(inventory);

        if (phase == SessionGuard.Phase.AWAITING_LOGIN) {
            inventory.setItem(LOGIN_SLOT, item(Material.TRIPWIRE_HOOK, "LOGIN", NamedTextColor.AQUA,
                    "Enter your password to log in."));
        } else if (phase == SessionGuard.Phase.AWAITING_REGISTRATION) {
            inventory.setItem(LOGIN_SLOT, item(Material.BARRIER, "LOGIN", NamedTextColor.DARK_GRAY,
                    "Register before you can log in."));
        } else {
            inventory.setItem(LOGIN_SLOT, item(Material.LIME_DYE, "LOGGED IN", NamedTextColor.GREEN,
                    "Your identity is verified."));
        }

        inventory.setItem(STATUS_SLOT, item(Material.SHIELD, "SECURITY STATUS", NamedTextColor.YELLOW,
                "Strong hashes • lockouts • protected session."));
        if (phase == SessionGuard.Phase.AWAITING_REGISTRATION) {
            inventory.setItem(ACTION_SLOT, item(Material.AMETHYST_SHARD, "REGISTER", NamedTextColor.LIGHT_PURPLE,
                    "Create a new server identity."));
        } else {
            inventory.setItem(ACTION_SLOT, item(Material.ENDER_EYE, "CHANGE PASSWORD", NamedTextColor.LIGHT_PURPLE,
                    "Confirm your old password first."));
        }
        show(player, flow, holder);
    }

    private void openPasswordEntry(final Player player, final Flow flow, final Screen screen) {
        final GateHolder holder = new GateHolder(screen);
        final Inventory inventory = Bukkit.createInventory(holder, org.bukkit.event.inventory.InventoryType.ANVIL,
                Component.text("Cipher Gate • " + screen.title, NamedTextColor.DARK_AQUA));
        holder.attach(inventory);
        final ItemStack entryToken = new ItemStack(Material.PAPER);
        final ItemMeta entryMeta = entryToken.getItemMeta();
        entryMeta.displayName(Component.empty());
        entryToken.setItemMeta(entryMeta);
        inventory.setItem(0, entryToken);
        show(player, flow, holder);
        player.sendMessage(Component.text(screen.instruction, NamedTextColor.GRAY));
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

    private static ItemStack item(final Material material, final String title, final NamedTextColor color,
                                  final String... lines) {
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
        MENU("", ""),
        LOGIN_ENTRY("Login", "Type your password in the rename field, then click CONTINUE."),
        REGISTER_ENTRY("Register", "Choose a password in the rename field, then click CONTINUE."),
        REGISTER_CONFIRM_ENTRY("Confirm Registration", "Enter the same password again, then click CONTINUE."),
        CHANGE_CURRENT_ENTRY("Current Password", "Enter your current password, then click CONTINUE."),
        CHANGE_NEW_ENTRY("New Password", "Choose a new password, then click CONTINUE."),
        CHANGE_CONFIRM_ENTRY("Confirm New Password", "Enter the new password again, then click CONTINUE.");

        private final String title;
        private final String instruction;

        Screen(final String title, final String instruction) {
            this.title = title;
            this.instruction = instruction;
        }

        private boolean isEntry() {
            return this != MENU;
        }
    }

    private static final class Flow {
        private GateHolder holder;
        private char[] registrationDraft;
        private char[] newPasswordDraft;
        private boolean changeAuthorized;
        private boolean waitingForCheck;

        private void clear() {
            if (registrationDraft != null) {
                Arrays.fill(registrationDraft, '\0');
                registrationDraft = null;
            }
            if (newPasswordDraft != null) {
                Arrays.fill(newPasswordDraft, '\0');
                newPasswordDraft = null;
            }
            changeAuthorized = false;
            waitingForCheck = false;
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
