package dev.ciphergate.auth;

import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

/**
 * A compact UUID-keyed store. It deliberately contains no player names, IP
 * addresses, or recoverable passwords.
 */
public final class AccountStore {
    private final JavaPlugin plugin;
    private final File accountFile;
    private final Map<UUID, Account> accounts = new ConcurrentHashMap<>();
    private final Object fileLock = new Object();

    public AccountStore(final JavaPlugin plugin) {
        this.plugin = plugin;
        this.accountFile = new File(plugin.getDataFolder(), "accounts.yml");
    }

    public void load() {
        if (!accountFile.exists()) {
            return;
        }
        final YamlConfiguration yaml = YamlConfiguration.loadConfiguration(accountFile);
        final ConfigurationSection players = yaml.getConfigurationSection("players");
        if (players == null) {
            return;
        }
        for (final String value : players.getKeys(false)) {
            try {
                final UUID uuid = UUID.fromString(value);
                final String prefix = value + ".";
                final String hash = players.getString(prefix + "hash", "");
                if (hash.isBlank()) {
                    continue;
                }
                accounts.put(uuid, new Account(
                        hash,
                        Math.max(0, players.getLong(prefix + "created-at", 0)),
                        Math.max(0, players.getLong(prefix + "password-changed-at", 0)),
                        Math.max(0, players.getInt(prefix + "failed-attempts", 0)),
                        Math.max(0, players.getLong(prefix + "locked-until", 0))
                ));
            } catch (final IllegalArgumentException ignored) {
                plugin.getLogger().warning("Ignored malformed account entry: " + value);
            }
        }
        plugin.getLogger().info("Loaded " + accounts.size() + " CipherGate account(s).");
    }

    public Account find(final UUID uuid) {
        return accounts.get(uuid);
    }

    public boolean contains(final UUID uuid) {
        return accounts.containsKey(uuid);
    }

    public int size() {
        return accounts.size();
    }

    public boolean create(final UUID uuid, final String passwordHash, final long now) {
        final boolean created = accounts.putIfAbsent(uuid, new Account(passwordHash, now, now, 0, 0)) == null;
        if (created) {
            save();
        }
        return created;
    }

    public Account recordFailure(final UUID uuid, final long now, final SecuritySettings settings) {
        final Account[] result = new Account[1];
        accounts.computeIfPresent(uuid, (ignored, account) -> {
            final Account next = account.failedLogin(now, settings);
            result[0] = next;
            return next;
        });
        if (result[0] != null) {
            save();
        }
        return result[0];
    }

    public void recordSuccess(final UUID uuid, final String upgradedHash, final long now) {
        accounts.computeIfPresent(uuid, (ignored, account) -> account.successfulLogin(upgradedHash, now));
        save();
    }

    public boolean unlock(final UUID uuid) {
        final boolean[] found = {false};
        accounts.computeIfPresent(uuid, (ignored, account) -> {
            found[0] = true;
            return account.unlocked();
        });
        if (found[0]) {
            save();
        }
        return found[0];
    }

    public void save() {
        synchronized (fileLock) {
            try {
                Files.createDirectories(accountFile.toPath().getParent());
                final YamlConfiguration yaml = new YamlConfiguration();
                yaml.set("schema-version", 1);
                for (final Map.Entry<UUID, Account> entry : accounts.entrySet()) {
                    final String path = "players." + entry.getKey() + ".";
                    final Account account = entry.getValue();
                    yaml.set(path + "hash", account.passwordHash());
                    yaml.set(path + "created-at", account.createdAt());
                    yaml.set(path + "password-changed-at", account.passwordChangedAt());
                    yaml.set(path + "failed-attempts", account.failedAttempts());
                    yaml.set(path + "locked-until", account.lockedUntil());
                }
                yaml.save(accountFile);
            } catch (final IOException exception) {
                plugin.getLogger().log(Level.SEVERE, "Could not save CipherGate accounts.yml", exception);
            }
        }
    }
}
