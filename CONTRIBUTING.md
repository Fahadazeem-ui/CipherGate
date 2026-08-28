# Contributing

Thanks for improving CipherGate.

1. Fork the repository and create a focused branch.
2. Use Java 21 and run mvn --batch-mode verify.
3. Keep changes privacy-conscious: do not add password, IP, or name tracking without a clear security reason and documentation.
4. Test the complete registration, login, timeout, lockout, reload, and reconnect flows on a Paper 1.21.11 test server.
5. Open a pull request explaining the behavior and any security trade-offs.

Never include real account files, credentials, or peppers in commits.
