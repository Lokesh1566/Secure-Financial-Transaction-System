package com.securepay.service;

import com.securepay.crypto.AESEncryptor;
import com.securepay.crypto.RSAKeyExchange;
import com.securepay.model.Transaction;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * Main service that handles the full transaction security flow:
 * 
 * 1. Generate AES session key for this transaction
 * 2. Encrypt the transaction payload with AES-256-GCM
 * 3. Encrypt the AES key with receiver's RSA public key
 * 4. Sign the encrypted payload with sender's RSA private key
 * 5. On the receiving end: verify signature, decrypt AES key, decrypt payload
 * 
 * This is basically how TLS works under the hood, simplified.
 * The hybrid approach gives us the best of both worlds:
 * - AES for fast bulk encryption of the actual data
 * - RSA for secure key exchange (no shared secret needed)
 * - Digital signatures for non-repudiation
 * 
 * @author Lokesh Reddy Elluri
 */
public class TransactionService {

    /**
     * Result of encrypting a transaction. Contains everything
     * the receiver needs to verify and decrypt.
     */
    public static class SecurePackage {
        public final String encryptedPayload;
        public final String encryptedAESKey;
        public final String digitalSignature;
        public final String transactionId;

        public SecurePackage(String encryptedPayload, String encryptedAESKey,
                            String digitalSignature, String transactionId) {
            this.encryptedPayload = encryptedPayload;
            this.encryptedAESKey = encryptedAESKey;
            this.digitalSignature = digitalSignature;
            this.transactionId = transactionId;
        }

        @Override
        public String toString() {
            return String.format(
                "SecurePackage {\n  txId: %s\n  payload: %s...\n  aesKey: %s...\n  sig: %s...\n}",
                transactionId,
                encryptedPayload.substring(0, Math.min(40, encryptedPayload.length())),
                encryptedAESKey.substring(0, Math.min(40, encryptedAESKey.length())),
                digitalSignature.substring(0, Math.min(40, digitalSignature.length()))
            );
        }
    }

    /**
     * Encrypt and sign a transaction.
     * 
     * Called by the sender. The receiver's public key is used to
     * protect the AES key, and the sender's private key signs the payload
     * so the receiver knows it's authentic.
     */
    public static SecurePackage encryptTransaction(
            Transaction tx,
            PublicKey receiverPublicKey,
            RSAKeyExchange senderKeys) throws Exception {

        // step 1: generate a fresh AES key for this transaction
        AESEncryptor aes = new AESEncryptor();

        // step 2: encrypt the transaction data
        String payload = tx.toPayloadString();
        String encryptedPayload = aes.encrypt(payload);

        // step 3: encrypt the AES key with receiver's RSA public key
        String encryptedAESKey = RSAKeyExchange.encryptKey(
            aes.getSecretKey(), receiverPublicKey
        );

        // step 4: sign the encrypted payload
        byte[] signature = senderKeys.sign(encryptedPayload.getBytes("UTF-8"));
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);

        // update transaction status
        tx.setStatus("ENCRYPTED");
        tx.setEncryptedPayload(encryptedPayload);
        tx.setDigitalSignature(signatureBase64);

        return new SecurePackage(encryptedPayload, encryptedAESKey,
                                signatureBase64, tx.getTransactionId());
    }

    /**
     * Verify and decrypt a received transaction.
     * 
     * Called by the receiver. First checks the signature to make sure
     * the sender is who they claim to be, then decrypts everything.
     */
    public static Transaction decryptTransaction(
            SecurePackage pkg,
            PrivateKey receiverPrivateKey,
            PublicKey senderPublicKey) throws Exception {

        // step 1: verify the sender's signature
        byte[] signature = Base64.getDecoder().decode(pkg.digitalSignature);
        boolean valid = RSAKeyExchange.verify(
            pkg.encryptedPayload.getBytes("UTF-8"),
            signature,
            senderPublicKey
        );

        if (!valid) {
            throw new SecurityException(
                "Signature verification FAILED for transaction " + pkg.transactionId +
                " — possible tampering detected!"
            );
        }

        // step 2: decrypt the AES key using our private key
        SecretKey aesKey = RSAKeyExchange.decryptKey(
            pkg.encryptedAESKey, receiverPrivateKey
        );

        // step 3: decrypt the payload with the recovered AES key
        AESEncryptor aes = new AESEncryptor(aesKey);
        String decryptedPayload = aes.decrypt(pkg.encryptedPayload);

        // step 4: parse the payload back into a transaction
        String[] fields = Transaction.parsePayload(decryptedPayload);
        Transaction tx = new Transaction(
            fields[1],  // sender
            fields[2],  // receiver
            Double.parseDouble(fields[3]),  // amount
            fields[4],  // currency
            fields[5]   // description
        );
        tx.setStatus("VERIFIED");

        return tx;
    }

    /**
     * Run a complete end-to-end test: create tx → encrypt → sign → verify → decrypt.
     * Returns true if the decrypted data matches the original.
     */
    public static boolean runIntegrityTest(Transaction original,
                                           RSAKeyExchange senderKeys,
                                           RSAKeyExchange receiverKeys) throws Exception {
        // sender encrypts
        SecurePackage pkg = encryptTransaction(
            original, receiverKeys.getPublicKey(), senderKeys
        );

        // receiver decrypts
        Transaction decrypted = decryptTransaction(
            pkg, receiverKeys.getPrivateKey(), senderKeys.getPublicKey()
        );

        // verify the data survived the round trip
        boolean amountMatch = Math.abs(original.getAmount() - decrypted.getAmount()) < 0.01;
        boolean senderMatch = original.getSenderId().equals(decrypted.getSenderId());
        boolean receiverMatch = original.getReceiverId().equals(decrypted.getReceiverId());
        boolean currencyMatch = original.getCurrency().equals(decrypted.getCurrency());

        return amountMatch && senderMatch && receiverMatch && currencyMatch;
    }
}
