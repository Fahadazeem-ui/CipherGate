# Changelog

## 1.0.1

- Relaxed the default password policy: passwords need only be 6 characters or longer.
- Uppercase letters, lowercase letters, digits, and symbols are all optional.

## 1.0.0

- Initial Paper 1.21.11 release.
- Added PBKDF2-SHA512 password storage with per-password salts, versioning, optional pepper support, and cost upgrades.
- Added protected authentication sessions, persistent lockouts, and an authentication timeout.
- Added the Cipher Gate menu and secure-entry flow.
