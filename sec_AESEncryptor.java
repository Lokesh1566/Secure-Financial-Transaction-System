package com.securepay.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256 encryption/decryption module.
 * 
 * Using GCM mode instead of CBC because it provides both
 * confidentiality AND integrity (authenticated encryption).
 * CBC only gives confidentiality — you'd need a separate HMAC
 * for integrity, which is more code and more room for mistakes.
 * 
 * GCM also doesn't need padding, so no padding oracle attacks.
 * 
 * @author Lokesh Reddy Elluri
 */
public class AESEncryptor {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;   // 96 bits, NIST recommended
    private static final int GCM_TAG_LENGTH = 128;  // 128 bit auth tag

    private final SecretKey secretKey;

    /**
     * Create with a new random key.
     */
    public AESEncryptor() throws Exception {
        this.secretKey = generateKey();
    }

    /**
     * Create with an existing key (for when we get the key from RSA exchange).
     */
    public AESEncryptor(SecretKey key) {
        this.secretKey = key;
    }

    /**
     * Create from a base64-encoded key string.
     * Useful for loading saved keys.
     */
    public AESEncryptor(String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, ALGORITHM);
    }

    /**
     * Generate a fresh AES-256 key.
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * Encrypt plaintext.
     * 
     * The IV gets prepended to the ciphertext so we can extract it
     * during decryption. Each encryption uses a unique random IV
     * (never reuse IVs with GCM — that completely breaks security).
     * 
     * @param plaintext the data to encrypt
     * @return base64-encoded string containing IV + ciphertext
     */
    public String encrypt(String plaintext) throws Exception {
        // generate a fresh IV for every encryption
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // prepend IV to ciphertext: [IV (12 bytes) | ciphertext + tag]
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypt ciphertext.
     * 
     * Extracts the IV from the first 12 bytes, then decrypts the rest.
     * GCM mode automatically verifies the auth tag — if someone tampered
     * with the data, this will throw an AEADBadTagException.
     * 
     * @param encryptedBase64 the base64 string from encrypt()
     * @return original plaintext
     */
    public String decrypt(String encryptedBase64) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);

        // extract IV from the beginning
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);

        // rest is ciphertext + auth tag
        byte[] ciphertext = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, "UTF-8");
    }

    /**
     * Get the key as base64 string (for storage or transmission).
     */
    public String getKeyAsBase64() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }
}
