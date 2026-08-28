package dev.ciphergate.auth;

import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Objects;

public final class CipherGatePlugin extends JavaPlugin {
    private SecuritySettings settings;
    private AccountStore accounts;
    private SessionGuard sessions;
    private AuthenticationService authentication;
    private GateMenu gate;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        settings = SecuritySettings.from(getConfig());
        accounts = new AccountStore(this);
        accounts.load();
        sessions = new SessionGuard(this, accounts, settings);
        authentication = new AuthenticationService(this, accounts, sessions, new PasswordHasher(settings), settings);
        gate = new GateMenu(this, sessions, authentication, settings);

        final CipherGateCommand commands = new CipherGateCommand(this);
        registerCommand("login", commands);
        registerCommand("register", commands);
        registerCommand("gate", commands);
        registerCommand("ciphergate", commands);
        getServer().getPluginManager().registerEvents(new AuthProtectionListener(this, sessions, gate), this);
        getServer().getScheduler().runTaskTimer(this, sessions::tick, 20L, 20L);
        getServer().getScheduler().runTask(this, () -> getServer().getOnlinePlayers().forEach(player -> {
            if (!sessions.isPending(player.getUniqueId())) {
                sessions.begin(player);
                if (sessions.isPending(player.getUniqueId()) && settings.showGateOnJoin()) {
                    gate.open(player);
                }
            }
        }));

        if (settings.pepper().isBlank()) {
            getLogger().warning("No CipherGate pepper is configured. Password hashes are still salted, but set "
                    + "CIPHERGATE_PEPPER or -Dciphergate.pepper for defense in depth.");
        }
        getLogger().info("CipherGate is armed for Paper 1.21.11.");
    }

    @Override
    public void onDisable() {
        if (gate != null) {
            getServer().getOnlinePlayers().forEach(player -> gate.forget(player.getUniqueId()));
        }
        if (accounts != null) {
            accounts.save();
        }
    }

    public void reloadCipherGate() {
        reloadConfig();
        settings = SecuritySettings.from(getConfig());
        sessions.setSettings(settings);
        authentication.setSettings(settings);
        gate.setSettings(settings);
        if (settings.pepper().isBlank()) {
            getLogger().warning("CipherGate reload completed without a pepper.");
        }
    }

    public SecuritySettings settings() {
        return settings;
    }

    public AccountStore accounts() {
        return accounts;
    }

    public AuthenticationService authentication() {
        return authentication;
    }

    public GateMenu gate() {
        return gate;
    }

    private void registerCommand(final String name, final CipherGateCommand executor) {
        final PluginCommand command = Objects.requireNonNull(getCommand(name), "Missing " + name + " in plugin.yml");
        command.setExecutor(executor);
        command.setTabCompleter(executor);
    }
}
