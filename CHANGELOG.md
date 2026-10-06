# Changelog

## 1.1.0

- Added an optional per-account IP lock: `/cg ip <address>` pins an account to one IP, and any other address is kicked on join even with the correct password.
- Added `/cg ip` (show lock and current address) and `/cg ip clear` (remove the lock). Setting or clearing requires a logged-in session.
- Added `/ciphergate ip <uuid|player> [address|clear]` so administrators can view, set, or rescue an IP lock, including from console.
- accounts.yml schema is now version 2 with an optional `allowed-ip` per account. Older files load without changes and stay unlocked until a lock is set.

## 1.0.3

- Removed the unreliable anvil password interface, including its XP cost.
- Added the reliable /changepassword <old> <new> <confirm> command.

## 1.0.2

- Fixed the Cipher Gate anvil submission button so clients can click and submit it.
- Renamed the gate actions to Login, Register, and Change Password.
- Added a three-step password-change flow that requires the current password, then a new password and confirmation.

## 1.0.1

- Relaxed the default password policy: passwords need only be 6 characters or longer.
- Uppercase letters, lowercase letters, digits, and symbols are all optional.

## 1.0.0

- Initial Paper 1.21.11 release.
- Added PBKDF2-SHA512 password storage with per-password salts, versioning, optional pepper support, and cost upgrades.
- Added protected authentication sessions, persistent lockouts, and an authentication timeout.
- Added the Cipher Gate menu and secure-entry flow.
