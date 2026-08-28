# Security Policy

## Supported versions

Security fixes are made on the latest 1.x release of CipherGate.

## Reporting a vulnerability

Do not open a public issue for a credential-handling or bypass vulnerability. Contact the repository owner privately and include:

- The affected CipherGate version
- Paper and Java versions
- A minimal reproduction
- The expected and observed behavior
- Any relevant configuration, with secrets removed

Please allow a reasonable time for acknowledgement and a fix before disclosure.

## Deployment hardening checklist

- Run Paper 1.21.11 with Java 21 and keep both updated.
- Use online-mode=true whenever possible.
- Generate a unique high-entropy CIPHERGATE_PEPPER outside the repository and plugin configuration.
- Restrict access to plugins/CipherGate/accounts.yml and your backups.
- Prefer /gate for password entry and audit any command-logging, chat, analytics, or moderation plugins.
- Use a TLS-protected control panel and a unique server-panel password.
- Make encrypted backups before upgrading Paper or modifying authentication settings.

## Threat-model boundaries

CipherGate protects the authentication state it owns. It cannot secure a compromised host, a malicious plugin with filesystem access, an untrusted proxy, a player looking at another player's screen, or a server configured to log credentials before CipherGate receives them.
