package com.securepay;

import com.securepay.crypto.AESEncryptor;
import com.securepay.crypto.RSAKeyExchange;
import com.securepay.model.Transaction;
import com.securepay.service.TransactionService;
import com.securepay.service.TransactionService.SecurePackage;
import com.securepay.util.TransactionBenchmark;

/**
 * Main entry point.
 * 
 * Demonstrates the full secure transaction flow and runs the benchmark.
 * 
 * Usage:
 *   javac -d out src/main/java/com/securepay/*.java src/main/java/com/securepay/**\/*.java
 *   java -cp out com.securepay.Main
 *   java -cp out com.securepay.Main --benchmark 10000
 * 
 * @author Lokesh Reddy Elluri
 */
public class Main {

    public static void main(String[] args) throws Exception {

        // check if user wants to run the benchmark
        if (args.length > 0 && args[0].equals("--benchmark")) {
            int count = args.length > 1 ? Integer.parseInt(args[1]) : 10000;
            TransactionBenchmark bench = new TransactionBenchmark();
            bench.run(count);
            return;
        }

        System.out.println("=".repeat(60));
        System.out.println("  SECURE FINANCIAL TRANSACTION SYSTEM");
        System.out.println("  AES-256-GCM + RSA-2048 Hybrid Encryption");
        System.out.println("=".repeat(60));
        System.out.println();

        // --- Demo 1: AES encryption ---
        System.out.println("[1] AES-256-GCM Encryption Demo");
        System.out.println("-".repeat(40));

        AESEncryptor aes = new AESEncryptor();
        String sensitive = "CARD:4532-8721-0098-3344|CVV:847|EXP:12/27";
        String encrypted = aes.encrypt(sensitive);
        String decrypted = aes.decrypt(encrypted);

        System.out.println("  Original:  " + sensitive);
        System.out.println("  Encrypted: " + encrypted.substring(0, 50) + "...");
        System.out.println("  Decrypted: " + decrypted);
        System.out.println("  Match:     " + sensitive.equals(decrypted));
        System.out.println();

        // --- Demo 2: RSA key exchange ---
        System.out.println("[2] RSA-2048 Key Exchange Demo");
        System.out.println("-".repeat(40));

        RSAKeyExchange alice = new RSAKeyExchange();
        RSAKeyExchange bob = new RSAKeyExchange();

        // alice encrypts her AES key with bob's public key
        String encKey = RSAKeyExchange.encryptKey(aes.getSecretKey(), bob.getPublicKey());
        // bob decrypts it with his private key
        javax.crypto.SecretKey recovered = RSAKeyExchange.decryptKey(encKey, bob.getPrivateKey());

        System.out.println("  Alice's AES key:     " + aes.getKeyAsBase64().substring(0, 30) + "...");
        System.out.println("  Encrypted (for Bob): " + encKey.substring(0, 30) + "...");
        System.out.println("  Bob decrypted:       " + java.util.Base64.getEncoder().encodeToString(recovered.getEncoded()).substring(0, 30) + "...");
        System.out.println("  Keys match:          " + aes.getKeyAsBase64().equals(
            java.util.Base64.getEncoder().encodeToString(recovered.getEncoded())));
        System.out.println();

        // --- Demo 3: Full transaction flow ---
        System.out.println("[3] Full Secure Transaction Flow");
        System.out.println("-".repeat(40));

        RSAKeyExchange senderKeys = new RSAKeyExchange();
        RSAKeyExchange receiverKeys = new RSAKeyExchange();

        Transaction tx = new Transaction(
            "ALICE-0001", "BOB-0042", 2500.75, "USD", "Invoice payment #4821"
        );
        System.out.println("  Original: " + tx);

        // encrypt & sign
        SecurePackage pkg = TransactionService.encryptTransaction(
            tx, receiverKeys.getPublicKey(), senderKeys
        );
        System.out.println("  Encrypted & signed.");
        System.out.println("  " + pkg);

        // verify & decrypt
        Transaction verified = TransactionService.decryptTransaction(
            pkg, receiverKeys.getPrivateKey(), senderKeys.getPublicKey()
        );
        System.out.println("  Verified & decrypted: " + verified);
        System.out.println();

        // --- Demo 4: Tamper detection ---
        System.out.println("[4] Tamper Detection Demo");
        System.out.println("-".repeat(40));

        try {
            // mess with the encrypted payload (simulate man-in-the-middle)
            String tampered = pkg.encryptedPayload.substring(0, pkg.encryptedPayload.length() - 5) + "XXXXX";
            SecurePackage fakePkg = new SecurePackage(
                tampered, pkg.encryptedAESKey, pkg.digitalSignature, pkg.transactionId
            );
            TransactionService.decryptTransaction(
                fakePkg, receiverKeys.getPrivateKey(), senderKeys.getPublicKey()
            );
            System.out.println("  ERROR: tamper not detected!");
        } catch (SecurityException e) {
            System.out.println("  Tampered payload detected: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("  Tampering caught (decryption failed): " + e.getClass().getSimpleName());
        }
        System.out.println();

        // --- Quick integrity test ---
        System.out.println("[5] Quick Integrity Test (100 transactions)");
        System.out.println("-".repeat(40));

        int passed = 0;
        for (int i = 0; i < 100; i++) {
            Transaction test = new Transaction(
                "S-" + i, "R-" + i, 100 + i * 10.5, "USD", "Test tx #" + i
            );
            if (TransactionService.runIntegrityTest(test, senderKeys, receiverKeys)) {
                passed++;
            }
        }
        System.out.printf("  Result: %d/100 passed%n", passed);
        System.out.println();

        System.out.println("Run full benchmark: java -cp out com.securepay.Main --benchmark 10000");
        System.out.println("=".repeat(60));
    }
}
