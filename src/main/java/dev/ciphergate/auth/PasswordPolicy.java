package dev.ciphergate.auth;

/** Password rules are deliberately checked before expensive hash work begins. */
public final class PasswordPolicy {
    private PasswordPolicy() {
    }

    public static String violation(final char[] password, final SecuritySettings settings) {
        if (password.length < settings.minimumPasswordLength()) {
            return "Password must contain at least " + settings.minimumPasswordLength() + " characters.";
        }
        if (password.length > settings.maximumPasswordLength()) {
            return "Password must be at most " + settings.maximumPasswordLength() + " characters.";
        }

        boolean uppercase = false;
        boolean lowercase = false;
        boolean digit = false;
        boolean symbol = false;
        for (final char character : password) {
            if (Character.isUpperCase(character)) {
                uppercase = true;
            } else if (Character.isLowerCase(character)) {
                lowercase = true;
            } else if (Character.isDigit(character)) {
                digit = true;
            } else {
                symbol = true;
            }
        }
        if (settings.requireUppercase() && !uppercase) {
            return "Password must include an uppercase letter.";
        }
        if (settings.requireLowercase() && !lowercase) {
            return "Password must include a lowercase letter.";
        }
        if (settings.requireDigit() && !digit) {
            return "Password must include a number.";
        }
        if (settings.requireSymbol() && !symbol) {
            return "Password must include a symbol.";
        }
        return null;
    }
}
