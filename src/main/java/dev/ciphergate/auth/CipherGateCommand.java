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
            case "gate" -> gate(sender);
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
            player.sendMessage(Component.text("For passwords containing spaces, use /gate instead.", NamedTextColor.GRAY));
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

    private boolean gate(final CommandSender sender) {
        final Player player = playerOnly(sender);
        if (player != null) {
            plugin.gate().open(player);
        }
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
        sender.sendMessage(Component.text("Usage: /ciphergate <status|reload|unlock <uuid>>", NamedTextColor.RED));
        return true;
    }

    @Override
    public List<String> onTabComplete(
            final CommandSender sender,
            final Command command,
            final String alias,
            final String[] args
    ) {
        if (!command.getName().equalsIgnoreCase("ciphergate") || !sender.hasPermission("ciphergate.admin")) {
            return Collections.emptyList();
        }
        return args.length == 1 ? List.of("status", "reload", "unlock") : Collections.emptyList();
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
