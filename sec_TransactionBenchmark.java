package com.securepay.util;

import com.securepay.crypto.RSAKeyExchange;
import com.securepay.model.Transaction;
import com.securepay.service.TransactionService;

import java.util.Random;

/**
 * Benchmark tool to run bulk transaction encryption tests.
 * 
 * This is what we used to validate the system across 10,000+ transactions.
 * Generates random transactions with varying amounts and currencies,
 * runs the full encrypt-sign-verify-decrypt cycle, and reports stats.
 * 
 * Typical results on my laptop (M1 MacBook):
 * - 10,000 transactions in ~45 seconds
 * - ~220 tx/sec throughput
 * - 0 integrity failures
 * 
 * @author Lokesh Reddy Elluri
 */
public class TransactionBenchmark {

    private static final String[] CURRENCIES = {"USD", "EUR", "GBP", "INR", "JPY"};
    private static final String[] DESCRIPTIONS = {
        "Online purchase", "Wire transfer", "Subscription payment",
        "Salary deposit", "Invoice payment", "Refund", "P2P transfer",
        "Bill payment", "Investment", "Loan repayment"
    };

    private final Random random = new Random(42);  // seeded for reproducibility

    /**
     * Run the benchmark with the specified number of transactions.
     */
    public void run(int numTransactions) throws Exception {
        System.out.println("=".repeat(60));
        System.out.println("  SECURE TRANSACTION BENCHMARK");
        System.out.println("=".repeat(60));
        System.out.printf("  Transactions to test: %,d%n", numTransactions);
        System.out.println();

        // generate RSA keys once (expensive operation)
        System.out.println("  Generating RSA-2048 key pairs...");
        long keyStart = System.currentTimeMillis();
        RSAKeyExchange senderKeys = new RSAKeyExchange();
        RSAKeyExchange receiverKeys = new RSAKeyExchange();
        long keyTime = System.currentTimeMillis() - keyStart;
        System.out.printf("  Key generation: %d ms%n%n", keyTime);

        int passed = 0;
        int failed = 0;
        long totalEncryptTime = 0;
        long totalDecryptTime = 0;

        System.out.println("  Running transactions...");
        long batchStart = System.currentTimeMillis();

        for (int i = 0; i < numTransactions; i++) {
            try {
                Transaction tx = generateRandomTransaction();

                // time encryption
                long encStart = System.nanoTime();
                TransactionService.SecurePackage pkg = TransactionService.encryptTransaction(
                    tx, receiverKeys.getPublicKey(), senderKeys
                );
                totalEncryptTime += (System.nanoTime() - encStart);

                // time decryption + verification
                long decStart = System.nanoTime();
                Transaction decrypted = TransactionService.decryptTransaction(
                    pkg, receiverKeys.getPrivateKey(), senderKeys.getPublicKey()
                );
                totalDecryptTime += (System.nanoTime() - decStart);

                // check integrity
                boolean amountOk = Math.abs(tx.getAmount() - decrypted.getAmount()) < 0.01;
                boolean senderOk = tx.getSenderId().equals(decrypted.getSenderId());
                boolean receiverOk = tx.getReceiverId().equals(decrypted.getReceiverId());

                if (amountOk && senderOk && receiverOk) {
                    passed++;
                } else {
                    failed++;
                    System.out.printf("  INTEGRITY FAIL at tx #%d: %s%n", i + 1, tx);
                }

            } catch (Exception e) {
                failed++;
                System.out.printf("  ERROR at tx #%d: %s%n", i + 1, e.getMessage());
            }

            // progress indicator (every 10%)
            if ((i + 1) % (numTransactions / 10) == 0) {
                int pct = (int) ((i + 1.0) / numTransactions * 100);
                System.out.printf("  [%3d%%] %,d / %,d completed%n", pct, i + 1, numTransactions);
            }
        }

        long totalTime = System.currentTimeMillis() - batchStart;

        // results
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("  RESULTS");
        System.out.println("=".repeat(60));
        System.out.printf("  Total transactions:  %,d%n", numTransactions);
        System.out.printf("  Passed:              %,d%n", passed);
        System.out.printf("  Failed:              %,d%n", failed);
        System.out.printf("  Success rate:        %.2f%%%n", (passed * 100.0 / numTransactions));
        System.out.println();
        System.out.printf("  Total time:          %,d ms (%.1f sec)%n", totalTime, totalTime / 1000.0);
        System.out.printf("  Throughput:          %.0f tx/sec%n", numTransactions * 1000.0 / totalTime);
        System.out.printf("  Avg encrypt time:    %.2f ms/tx%n", totalEncryptTime / 1e6 / numTransactions);
        System.out.printf("  Avg decrypt time:    %.2f ms/tx%n", totalDecryptTime / 1e6 / numTransactions);
        System.out.println();
        System.out.println("  Encryption: AES-256-GCM (authenticated)");
        System.out.println("  Key Exchange: RSA-2048 OAEP");
        System.out.println("  Signatures: SHA256withRSA");
        System.out.println("=".repeat(60));
    }

    private Transaction generateRandomTransaction() {
        String sender = "USER-" + String.format("%04d", random.nextInt(1000));
        String receiver = "USER-" + String.format("%04d", random.nextInt(1000));
        double amount = Math.round(random.nextDouble() * 50000 * 100.0) / 100.0;  // up to $50k
        String currency = CURRENCIES[random.nextInt(CURRENCIES.length)];
        String desc = DESCRIPTIONS[random.nextInt(DESCRIPTIONS.length)];
        return new Transaction(sender, receiver, amount, currency, desc);
    }
}
