package dev.ciphergate.auth;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Commands stay small; all sensitive work is delegated to AuthenticationService. */
public final class CipherGateCommand implements CommandExecutor, TabCompleter {
    private final CipherGatePlugin plugin;

    public CipherGateCommand(final CipherGatePlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(
            final CommandSender sender,
            final Command command,
            final String label,
            final String[] args
    ) {
        return switch (command.getName().toLowerCase(Locale.ROOT)) {
            case "login" -> login(sender, args);
            case "register" -> register(sender, args);
            case "changepassword" -> changePassword(sender, args);
            case "gate" -> gate(sender, args);
            case "ciphergate" -> admin(sender, args);
            default -> false;
        };
    }

    private boolean login(final CommandSender sender, final String[] args) {
        final Player player = playerOnly(sender);
        if (player == null) {
            return true;
        }
        if (args.length == 0) {
            player.sendMessage(Component.text("Usage: /login <password>", NamedTextColor.RED));
            return true;
        }
        // Joining preserves spaces for people who choose a passphrase.
        final char[] password = String.join(" ", args).toCharArray();
        plugin.authentication().login(player, password);
        return true;
    }

    private boolean register(final CommandSender sender, final String[] args) {
        final Player player = playerOnly(sender);
        if (player == null) {
            return true;
        }
        if (args.length != 2) {
            player.sendMessage(Component.text("Usage: /register <password> <confirm>", NamedTextColor.RED));
            player.sendMessage(Component.text("Passwords cannot contain spaces when using this command.", NamedTextColor.GRAY));
            return true;
        }
        final char[] password = args[0].toCharArray();
        final char[] confirmation = args[1].toCharArray();
        if (!constantTimeEquals(password, confirmation)) {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            player.sendMessage(Component.text("Passwords did not match.", NamedTextColor.RED));
            return true;
        }
        Arrays.fill(confirmation, '\0');
        final String violation = PasswordPolicy.violation(password, plugin.settings());
        if (violation != null) {
            Arrays.fill(password, '\0');
            player.sendMessage(Component.text(violation, NamedTextColor.RED));
            return true;
        }
        plugin.authentication().register(player, password);
        return true;
    }

    private boolean changePassword(final CommandSender sender, final String[] args) {
        final Player player = playerOnly(sender);
        if (player == null) {
            return true;
        }
        if (args.length != 3) {
            player.sendMessage(Component.text("Usage: /changepassword <old> <new> <confirm>", NamedTextColor.RED));
            player.sendMessage(Component.text("Passwords cannot contain spaces when using this command.", NamedTextColor.GRAY));
            return true;
        }
        if (!plugin.accounts().contains(player.getUniqueId())) {
            player.sendMessage(Component.text("Register an account before changing its password.", NamedTextColor.RED));
            return true;
        }

        final char[] oldPassword = args[0].toCharArray();
        final char[] newPassword = args[1].toCharArray();
        final char[] confirmation = args[2].toCharArray();
        if (!constantTimeEquals(newPassword, confirmation)) {
            Arrays.fill(oldPassword, '\0');
            Arrays.fill(newPassword, '\0');
            Arrays.fill(confirmation, '\0');
            player.sendMessage(Component.text("New passwords did not match.", NamedTextColor.RED));
            return true;
        }
        Arrays.fill(confirmation, '\0');
        final String violation = PasswordPolicy.violation(newPassword, plugin.settings());
        if (violation != null) {
            Arrays.fill(oldPassword, '\0');
            Arrays.fill(newPassword, '\0');
            player.sendMessage(Component.text(violation, NamedTextColor.RED));
            return true;
        }

        plugin.authentication().verifyCurrentPassword(player, oldPassword, check -> {
            if (!player.isOnline()) {
                Arrays.fill(newPassword, '\0');
                return;
            }
            if (check == AuthenticationService.PasswordCheck.VERIFIED) {
                plugin.authentication().changePassword(player, newPassword, update -> {
                    if (!player.isOnline() || update == AuthenticationService.PasswordUpdate.UPDATED) {
                        return;
                    }
                    player.sendMessage(Component.text(update == AuthenticationService.PasswordUpdate.LOCKED
                            ? "Your account is temporarily locked."
                            : "CipherGate could not update your password. Try again.", NamedTextColor.RED));
                });
            } else {
                Arrays.fill(newPassword, '\0');
                player.sendMessage(Component.text(check == AuthenticationService.PasswordCheck.LOCKED
                        ? "Too many failed attempts. Your account is temporarily locked."
                        : (check == AuthenticationService.PasswordCheck.ERROR
                        ? "CipherGate could not verify your current password. Try again."
                        : "Current password was incorrect."), NamedTextColor.RED));
            }
        });
        return true;
    }

    private boolean gate(final CommandSender sender, final String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("ip")) {
            return ipSelf(sender, Arrays.copyOfRange(args, 1, args.length));
        }
        final Player player = playerOnly(sender);
        if (player != null) {
            plugin.gate().open(player);
        }
        return true;
    }

    /**
     * Self-service IP lock. Viewing the status is harmless before login, but
     * setting or clearing the lock requires a verified session so only the
     * real account owner can pin the account to an address.
     */
    private boolean ipSelf(final CommandSender sender, final String[] args) {
        final Player player = playerOnly(sender);
        if (player == null) {
            return true;
        }
        final Account account = plugin.accounts().find(player.getUniqueId());
        if (account == null) {
            player.sendMessage(Component.text("Create an account first with /register <password> <confirm>.",
                    NamedTextColor.RED));
            return true;
        }
        if (args.length == 0) {
            final String current = IpLocks.currentIp(player);
            if (account.hasIpLock()) {
                player.sendMessage(Component.text("IP lock: " + account.allowedIp(), NamedTextColor.AQUA));
                player.sendMessage(Component.text("Only that address can log in to your account.",
                        NamedTextColor.GRAY));
            } else {
                player.sendMessage(Component.text("IP lock: off. Any address can log in with your password.",
                        NamedTextColor.GRAY));
                player.sendMessage(Component.text("Lock it with /cg ip <address>.", NamedTextColor.GRAY));
            }
            player.sendMessage(Component.text("Your current address: "
                    + (current.isBlank() ? "unknown" : current), NamedTextColor.GRAY));
            return true;
        }
        if (!plugin.sessions().isAuthenticated(player.getUniqueId())) {
            player.sendMessage(Component.text("Log in first with /login <password>, then manage your IP lock.",
                    NamedTextColor.RED));
            return true;
        }
        if (args.length == 1 && (args[0].equalsIgnoreCase("clear") || args[0].equalsIgnoreCase("off"))) {
            plugin.accounts().clearAllowedIp(player.getUniqueId());
            player.sendMessage(Component.text("IP lock removed. Your account can log in from any address.",
                    NamedTextColor.GREEN));
            return true;
        }
        if (args.length == 1) {
            final String normalized = IpLocks.normalize(args[0]);
            if (normalized == null) {
                player.sendMessage(Component.text("That is not a valid IP address. Usage: /cg ip <address>",
                        NamedTextColor.RED));
                return true;
            }
            plugin.accounts().setAllowedIp(player.getUniqueId(), normalized);
            player.sendMessage(Component.text("This account is now locked to " + normalized + ".",
                    NamedTextColor.GREEN));
            player.sendMessage(Component.text(
                    "Only that address can log in, even with the correct password.", NamedTextColor.GRAY));
            if (!IpLocks.matches(normalized, IpLocks.currentIp(player))) {
                player.sendMessage(Component.text(
                        "Warning: that is not the address you are connected from. "
                                + "You will be locked out on your next join.",
                        NamedTextColor.YELLOW));
            }
            return true;
        }
        player.sendMessage(Component.text("Usage: /cg ip [address|clear]", NamedTextColor.RED));
        return true;
    }

    private boolean admin(final CommandSender sender, final String[] args) {
        if (!sender.hasPermission("ciphergate.admin")) {
            sender.sendMessage(Component.text("You do not have permission to manage CipherGate.", NamedTextColor.RED));
            return true;
        }
        if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
            sender.sendMessage(Component.text("CipherGate • " + plugin.accounts().size() + " account(s) • "
                    + plugin.settings().pbkdf2Iterations() + " PBKDF2 iterations", NamedTextColor.AQUA));
            return true;
        }
        if (args[0].equalsIgnoreCase("reload")) {
            plugin.reloadCipherGate();
            sender.sendMessage(Component.text("CipherGate configuration reloaded.", NamedTextColor.GREEN));
            return true;
        }
        if (args[0].equalsIgnoreCase("unlock") && args.length == 2) {
            try {
                final UUID uuid = UUID.fromString(args[1]);
                final boolean unlocked = plugin.accounts().unlock(uuid);
                sender.sendMessage(Component.text(unlocked ? "Account lock cleared." : "No account exists for that UUID.",
                        unlocked ? NamedTextColor.GREEN : NamedTextColor.YELLOW));
            } catch (final IllegalArgumentException exception) {
                sender.sendMessage(Component.text("Usage: /ciphergate unlock <uuid>", NamedTextColor.RED));
            }
            return true;
        }
        if (args[0].equalsIgnoreCase("ip")) {
            return adminIp(sender, Arrays.copyOfRange(args, 1, args.length));
        }
        sender.sendMessage(Component.text("Usage: /ciphergate <status|reload|unlock <uuid>|ip <uuid|player> [address|clear]>",
                NamedTextColor.RED));
        return true;
    }

    /**
     * Administrator IP-lock control. Accepts a UUID or an online player name
     * so a locked-out player (whose address changed) can be rescued without
     * editing accounts.yml by hand.
     */
    private boolean adminIp(final CommandSender sender, final String[] args) {
        if (args.length < 1 || args.length > 2) {
            sender.sendMessage(Component.text("Usage: /ciphergate ip <uuid|player> [address|clear]",
                    NamedTextColor.RED));
            return true;
        }
        final UUID target = resolveTarget(args[0]);
        if (target == null) {
            sender.sendMessage(Component.text("No online player or valid UUID matches '" + args[0] + "'.",
                    NamedTextColor.RED));
            return true;
        }
        final Account account = plugin.accounts().find(target);
        if (account == null) {
            sender.sendMessage(Component.text("No CipherGate account exists for that player.",
                    NamedTextColor.YELLOW));
            return true;
        }
        if (args.length == 1) {
            sender.sendMessage(Component.text(account.hasIpLock()
                    ? "IP lock: " + account.allowedIp()
                    : "IP lock: off", NamedTextColor.AQUA));
            return true;
        }
        if (args[1].equalsIgnoreCase("clear") || args[1].equalsIgnoreCase("off")) {
            plugin.accounts().clearAllowedIp(target);
            sender.sendMessage(Component.text("IP lock cleared.", NamedTextColor.GREEN));
            return true;
        }
        final String normalized = IpLocks.normalize(args[1]);
        if (normalized == null) {
            sender.sendMessage(Component.text("That is not a valid IP address.", NamedTextColor.RED));
            return true;
        }
        plugin.accounts().setAllowedIp(target, normalized);
        sender.sendMessage(Component.text("Account locked to " + normalized + ".", NamedTextColor.GREEN));
        return true;
    }

    private UUID resolveTarget(final String value) {
        try {
            return UUID.fromString(value);
        } catch (final IllegalArgumentException ignored) {
            // Fall through to the online-player lookup below.
        }
        final Player online = plugin.getServer().getPlayerExact(value);
        return online == null ? null : online.getUniqueId();
    }

    @Override
    public List<String> onTabComplete(
            final CommandSender sender,
            final Command command,
            final String alias,
            final String[] args
    ) {
        final String name = command.getName().toLowerCase(Locale.ROOT);
        if (name.equals("gate")) {
            if (args.length == 1) {
                return List.of("ip");
            }
            if (args.length == 2 && args[0].equalsIgnoreCase("ip")) {
                return List.of("clear");
            }
            return Collections.emptyList();
        }
        if (!name.equals("ciphergate") || !sender.hasPermission("ciphergate.admin")) {
            return Collections.emptyList();
        }
        if (args.length == 1) {
            return List.of("status", "reload", "unlock", "ip");
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("ip")) {
            return null; // Defer to the default online-player-name completion.
        }
        if (args.length == 3 && args[0].equalsIgnoreCase("ip")) {
            return List.of("clear");
        }
        return Collections.emptyList();
    }

    private static Player playerOnly(final CommandSender sender) {
        if (sender instanceof Player player) {
            return player;
        }
        sender.sendMessage(Component.text("This command can only be used in-game.", NamedTextColor.RED));
        return null;
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
}
