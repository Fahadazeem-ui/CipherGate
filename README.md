# CipherGate

**CipherGate** is a deliberately focused authentication plugin for **Paper 1.21.11**. It protects a server with a strong, calm login experience instead of turning authentication into a noisy minigame.

Players arrive at a small **Cipher Gate**: a polished in-game menu with a secure-entry path, clear commands, a visible timeout, and no ability to interact with the server until their identity is verified.

> Important: CipherGate is designed for a Paper server running Java Edition in online-mode=true. Authentication plugins can reduce risk on offline-mode servers, but cannot make a cracked/offline-mode identity model equivalent to Mojang account authentication.

## Highlights

- PBKDF2-HMAC-SHA512 password hashes with a unique 24-byte salt and 310,000 iterations by default
- Flexible default passwords: only 6 characters are required; character types are optional
- Versioned hash format with automatic cost upgrades after a successful login
- Optional server-side **pepper**, loaded from an environment variable or JVM property rather than committed to config
- Constant-time hash and confirmation comparisons
- Per-account persistent failed-attempt counter and timed lockout
- Password hashing runs off the main server thread
- Every join requires authentication by default; there is no IP-based bypass to weaken the model
- A pre-auth sandbox blocks movement, chat, commands, damage, inventory access, interactions, item use, drops, pickups, attacks, and projectiles
- 90-second authentication deadline (configurable)
- UUID-only storage: no player name history, IP history, or plaintext passwords
- An optional /gate UI using an anvil entry field, which keeps the password out of chat messages and clears the temporary inventory after submission

## Compatibility

| Requirement | Version |
| --- | --- |
| Server | Paper 1.21.11 |
| Java | 21 |
| Dependencies | None |
| Plugin API | Bukkit / Paper API |

Paper lists Java 21 as the recommended Java version for Paper 1.20 through 1.21.11. See the [Paper getting-started guide](https://docs.papermc.io/paper/getting-started/).

## Install

1. Download or build CipherGate-1.0.2.jar.
2. Put it in your server's plugins/ directory.
3. Start Paper once to create plugins/CipherGate/config.yml.
4. Set a high-entropy pepper outside the plugin config:
   - Environment variable: CIPHERGATE_PEPPER
   - JVM property: -Dciphergate.pepper=your-long-random-secret
5. Restart the server.

Do not change a live pepper casually: existing password hashes use it, so changing it invalidates password verification. Rotate it only through a planned account reset/migration.

## Player flow

On first join, CipherGate opens a small gate menu:

- **Login** opens the secure-entry screen for an existing account.
- **Register** starts a two-step password registration flow for a new account.
- **Change Password** replaces Register after account creation and requires the current password first.
- **Security status** shows the active authentication policy.

Players can also use:

    /login <password>
    /register <password> <confirm>
    /gate

/register command arguments cannot include spaces because it needs two separate values. Use /gate if the password contains spaces. The gate keeps the entry out of chat; as with any visible text field, the player should still be mindful of shoulder surfing.

## Administration

    /ciphergate status
    /ciphergate reload
    /ciphergate unlock <uuid>

| Permission | Default | Purpose |
| --- | --- | --- |
| ciphergate.use | Everyone | Login, registration, and gate commands |
| ciphergate.admin | OP | Status, reload, and account unlock |

CipherGate intentionally asks for a UUID when unlocking an account. Its account file does not retain player names.

## Configuration

The generated config.yml is fully annotated. The high-impact settings are:

    authentication:
      timeout-seconds: 90
      max-failed-attempts: 5
      lockout-minutes: 10

    passwords:
      minimum-length: 6
      require-uppercase: false
      require-lowercase: false
      require-digit: false
      pbkdf2-iterations: 310000

    security:
      pepper: ''
      block-chat-before-login: true
      show-gate-on-join: true

The hash format records its iteration count. Increasing pbkdf2-iterations is safe: CipherGate upgrades an existing hash after the user's next successful login. Decreasing it does not downgrade stored hashes.

## Data handling

plugins/CipherGate/accounts.yml contains only:

- UUID
- Versioned salted password hash
- Creation/password-change timestamps
- Failed-attempt count and lockout expiry

It never contains a plaintext password, a reversible encrypted password, an IP address, or a player name. Back up this file securely and never publish it.

## Build from source

    mvn --batch-mode package

The resulting JAR is written to target/CipherGate-1.0.2.jar. The GitHub Actions workflow verifies the same Maven build on Java 21.

## Security notes

No plugin can protect credentials if another plugin, proxy, host process, or command logger records user commands. Prefer /gate for player-facing password entry, review your other plugins, and restrict filesystem access to server operators. See [SECURITY.md](SECURITY.md) for reporting and deployment guidance.

## License

CipherGate is released under the [MIT License](LICENSE).
