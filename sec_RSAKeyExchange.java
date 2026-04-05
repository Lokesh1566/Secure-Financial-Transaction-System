package com.securepay.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA module for asymmetric key exchange.
 * 
 * The idea: we can't just send the AES key in plaintext over the network.
 * RSA lets us encrypt the AES key with the receiver's public key, so only
 * they can decrypt it with their private key. Classic hybrid encryption.
 * 
 * Using 2048-bit keys because 1024 is considered weak now. 4096 would be
 * safer but the performance hit isn't worth it for this use case.
 * 
 * We use OAEP padding instead of PKCS1 because PKCS1v1.5 is vulnerable
 * to Bleichenbacher's attack. OAEP is the recommended standard.
 * 
 * @author Lokesh Reddy Elluri
 */
public class RSAKeyExchange {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int KEY_SIZE = 2048;

    private final KeyPair keyPair;

    /**
     * Generate a fresh RSA key pair.
     */
    public RSAKeyExchange() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        this.keyPair = keyGen.generateKeyPair();
    }

    /**
     * Create from existing keys (loaded from storage).
     */
    public RSAKeyExchange(PublicKey publicKey, PrivateKey privateKey) {
        this.keyPair = new KeyPair(publicKey, privateKey);
    }

    /**
     * Encrypt an AES key using the receiver's public key.
     * 
     * In a real system this would happen on the sender's side:
     * 1. Sender gets receiver's public key
     * 2. Sender encrypts the AES session key with it
     * 3. Sends the encrypted key over the network
     * 4. Receiver decrypts with their private key
     * 
     * @param aesKey the symmetric key to protect
     * @param receiverPublicKey the receiver's RSA public key
     * @return base64-encoded encrypted key
     */
    public static String encryptKey(SecretKey aesKey, PublicKey receiverPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        byte[] encrypted = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt an AES key using our private key.
     * 
     * @param encryptedKeyBase64 the encrypted key from encryptKey()
     * @param privateKey our RSA private key
     * @return the original AES SecretKey
     */
    public static SecretKey decryptKey(String encryptedKeyBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedKeyBase64));
        return new SecretKeySpec(decrypted, "AES");
    }

    /**
     * Sign data with our private key.
     * Used to verify the sender's identity — the receiver can check
     * the signature using the sender's public key.
     */
    public byte[] sign(byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    /**
     * Verify a signature using the signer's public key.
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // -- key serialization helpers --

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(spec);
    }

    public static PrivateKey privateKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(spec);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
}
