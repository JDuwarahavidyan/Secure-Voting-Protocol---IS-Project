import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.SecretKey;

public class Voter {

    private final KeyPair dhKeyPair;

    public Voter() throws Exception {
        this.dhKeyPair = CryptoUtils.generateDHKeyPair(); // For DH key exchange
    }

    public PublicKey getVoterDHPublicKey() {
        return dhKeyPair.getPublic();
    }

    public PrivateKey getVoterDHPrivateKey() {
        return dhKeyPair.getPrivate();
    }

    // Generates token = UUID || timestamp
    public String issueToken() {
        String uuid = UUID.randomUUID().toString();
        String timestamp = ZonedDateTime.now(ZoneId.of("Asia/Colombo")).toString();
        return uuid + "|" + timestamp;
    }

    public boolean verifyToken(String tokenData, String signatureBase64, PublicKey authorityPubKey) throws Exception {
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return CryptoUtils.verifySHA256withRSA(tokenData.getBytes(), signature, authorityPubKey);
    }

    // Prepares the encrypted vote to send to EA using hybrid encryption (AES + RSA)
    public String prepareEncryptedVote(String vote, String token, String signedTokenBase64, PublicKey authorityRSAPubKey) throws Exception {
        
    	System.out.println("\n========== Voter: Prepare Encrypted Vote ==========");

        // Create ballot = H(vote)
        String ballot = CryptoUtils.hashSHA256(vote);
        String timestamp = ZonedDateTime.now(ZoneId.of("Asia/Colombo")).toString();
        System.out.println("Ballot (Hash)    : " + ballot);
        System.out.println("Timestamp        : " + timestamp);
        System.out.println("Token            : " + token);
        System.out.println("Signed Token     : " + signedTokenBase64);

        // Compose the plaintext payload
        String payload = ballot + "|" + timestamp + "|" + token + "|" + signedTokenBase64;

        // Generate AES key and encrypt the payload
        SecretKey aesKey = CryptoUtils.generateAESKey();
        byte[] encryptedPayload = CryptoUtils.encryptAES(payload.getBytes(), aesKey);

        // Encrypt the AES key with EA's RSA public key
        byte[] encryptedAESKey = CryptoUtils.encryptRSA(aesKey.getEncoded(), authorityRSAPubKey);

        // Combine encrypted AES key and encrypted payload
        String encryptedAESKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);
        String encryptedPayloadBase64 = Base64.getEncoder().encodeToString(encryptedPayload);

        String finalPackage = encryptedAESKeyBase64 + ":" + encryptedPayloadBase64;

        System.out.println("Encrypted Vote : " + finalPackage);

        return finalPackage;
    }
}
