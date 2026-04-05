package com.securepay.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Represents a financial transaction.
 * 
 * Kept it simple — just the essential fields you'd see in any
 * payment system. The actual encryption happens at the service layer,
 * not here (separation of concerns and all that).
 * 
 * @author Lokesh Reddy Elluri
 */
public class Transaction {

    private String transactionId;
    private String senderId;
    private String receiverId;
    private double amount;
    private String currency;
    private String description;
    private String status;  // PENDING, ENCRYPTED, VERIFIED, COMPLETED, FAILED
    private LocalDateTime timestamp;

    // encrypted payload (filled after encryption)
    private String encryptedPayload;
    private String digitalSignature;

    public Transaction(String senderId, String receiverId, double amount,
                       String currency, String description) {
        this.transactionId = UUID.randomUUID().toString().substring(0, 12).toUpperCase();
        this.senderId = senderId;
        this.receiverId = receiverId;
        this.amount = amount;
        this.currency = currency;
        this.description = description;
        this.status = "PENDING";
        this.timestamp = LocalDateTime.now();
    }

    /**
     * Build the plaintext payload that gets encrypted.
     * This is what we actually protect with AES.
     */
    public String toPayloadString() {
        return String.join("|",
            transactionId,
            senderId,
            receiverId,
            String.format("%.2f", amount),
            currency,
            description,
            timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        );
    }

    /**
     * Parse a decrypted payload back into field values.
     * Returns a string array: [txId, sender, receiver, amount, currency, desc, time]
     */
    public static String[] parsePayload(String payload) {
        return payload.split("\\|");
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %s | %.2f %s | %s | %s",
            transactionId, senderId, receiverId, amount, currency, description, status);
    }

    // -- getters and setters --
    // yeah I know lombok exists but didn't want to add a dependency for this

    public String getTransactionId() { return transactionId; }
    public String getSenderId() { return senderId; }
    public String getReceiverId() { return receiverId; }
    public double getAmount() { return amount; }
    public String getCurrency() { return currency; }
    public String getDescription() { return description; }
    public String getStatus() { return status; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getEncryptedPayload() { return encryptedPayload; }
    public String getDigitalSignature() { return digitalSignature; }

    public void setStatus(String status) { this.status = status; }
    public void setEncryptedPayload(String payload) { this.encryptedPayload = payload; }
    public void setDigitalSignature(String sig) { this.digitalSignature = sig; }
}
