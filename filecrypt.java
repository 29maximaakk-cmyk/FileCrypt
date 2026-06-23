// filecrypt.java
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class filecrypt {
    private static final String RESET = "\u001B[0m";
    private static final String GREEN = "\u001B[92m";
    private static final String RED = "\u001B[91m";
    private static final String YELLOW = "\u001B[93m";

    private static String colorize(String text, String color) {
        return color + text + RESET;
    }

    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;
    private static final int KEY_LEN = 32;
    private static final int ITERATIONS = 100000;

    private static byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN * 8);
        SecretKey tmp = factory.generateSecret(spec);
        return tmp.getEncoded();
    }

    private static void encryptFile(String inputPath, String outputPath, String password) throws Exception {
        SecureRandom rng = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        rng.nextBytes(salt);
        rng.nextBytes(nonce);

        byte[] key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LEN * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);

        byte[] plaintext = Files.readAllBytes(Paths.get(inputPath));
        byte[] ciphertext = cipher.doFinal(plaintext);

        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            fos.write(salt);
            fos.write(nonce);
            fos.write(ciphertext);
        }
        System.out.println(colorize("File encrypted successfully: " + outputPath, GREEN));
    }

    private static void decryptFile(String inputPath, String outputPath, String password) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputPath));
        if (data.length < SALT_LEN + NONCE_LEN + TAG_LEN)
            throw new Exception("Invalid file format");

        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        System.arraycopy(data, 0, salt, 0, SALT_LEN);
        System.arraycopy(data, SALT_LEN, nonce, 0, NONCE_LEN);
        int cipherLen = data.length - SALT_LEN - NONCE_LEN;
        byte[] ciphertext = new byte[cipherLen];
        System.arraycopy(data, SALT_LEN + NONCE_LEN, ciphertext, 0, cipherLen);

        byte[] key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LEN * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        Files.write(Paths.get(outputPath), plaintext);
        System.out.println(colorize("File decrypted successfully: " + outputPath, GREEN));
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println(colorize("Usage: java filecrypt encrypt|decrypt <input> <output> <password>", YELLOW));
            return;
        }
        String mode = args[0];
        String input = args[1];
        String output = args[2];
        String password = args[3];

        try {
            if (mode.equals("encrypt")) encryptFile(input, output, password);
            else if (mode.equals("decrypt")) decryptFile(input, output, password);
            else throw new Exception("Invalid mode. Use encrypt or decrypt.");
        } catch (Exception e) {
            System.err.println(colorize("Error: " + e.getMessage(), RED));
        }
    }
}
