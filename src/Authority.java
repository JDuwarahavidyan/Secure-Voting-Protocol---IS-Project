import java.io.*;
import java.security.*;
import java.time.*;
import java.util.*;
import javax.crypto.SecretKey;

public class Authority {
    private final KeyPair rsaKeyPair;
    private final KeyPair dhKeyPair;
    private final Map<String, Boolean> tokenIssuedMap = new HashMap<>();
    private static final String TRACKING_FILE = "signed_token_users.csv";

    public Authority() throws Exception {
        this.rsaKeyPair = CryptoUtils.generateRSAKeyPair();
        this.dhKeyPair = CryptoUtils.generateDHKeyPair();
        loadIssuedTokens();
    }

    public PublicKey getRSAPublicKey() {
        return rsaKeyPair.getPublic();
    }

    public PrivateKey getRSAPrivateKey() {
        return rsaKeyPair.getPrivate();
    }

    public PublicKey getDHPublicKey() {
        return dhKeyPair.getPublic();
    }

    public PrivateKey getDHPrivateKey() {
        return dhKeyPair.getPrivate();
    }

    public String getCertificate() {
        return Base64.getEncoder().encodeToString(getRSAPublicKey().getEncoded());
    }

    public boolean hasUserReceivedSignedToken(String username) {
        return tokenIssuedMap.getOrDefault(username, false);
    }

    public String respondToTokenRequest(String username, String token, PublicKey voterDHPubKey) throws Exception {
        

        byte[] signed = CryptoUtils.signSHA256withRSA(token.getBytes(), getRSAPrivateKey());
        String signedToken = Base64.getEncoder().encodeToString(signed);
        SecretKey sharedKey = CryptoUtils.deriveSharedSecret(getDHPrivateKey(), voterDHPubKey);
        byte[] encrypted = CryptoUtils.encryptWithSharedSecret(signedToken.getBytes(), sharedKey);

        tokenIssuedMap.put(username, true);
        saveIssuedTokens();

        return Base64.getEncoder().encodeToString(encrypted);
    }

    private void loadIssuedTokens() throws IOException {
        File file = new File(TRACKING_FILE);
        if (!file.exists()) return;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.strip().split(",");
                if (parts.length == 2) {
                    tokenIssuedMap.put(parts[0], parts[1].equals("1"));
                }
            }
        }
    }

    private void saveIssuedTokens() throws IOException {
        try (FileWriter writer = new FileWriter(TRACKING_FILE, false)) {
            for (var entry : tokenIssuedMap.entrySet()) {
                writer.write(entry.getKey() + "," + (entry.getValue() ? "1" : "0") + "\n");
            }
        }
    }

    public void processVote(String hybridEncryptedBase64) throws Exception {
        String[] parts = hybridEncryptedBase64.split(":", 2);
        if (parts.length != 2) {
            System.out.println("Invalid vote format received.");
            return;
        }

        byte[] encryptedAESKey = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedPayload = Base64.getDecoder().decode(parts[1]);

        byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedAESKey, getRSAPrivateKey());
        SecretKey aesKey = CryptoUtils.rebuildAESKey(aesKeyBytes);

        String decrypted = new String(CryptoUtils.decryptAES(encryptedPayload, aesKey));

        String[] payloadParts = decrypted.split("\\|", 5);
        if (payloadParts.length != 5) {
            System.out.println("Decrypted payload is not properly formatted.");
            return;
        }

        String ballot = payloadParts[0];
        String timestamp = payloadParts[1];
        String token = payloadParts[2] + "|" + payloadParts[3];
        String signedToken = payloadParts[4];

        System.out.println("\n=========== Decrypted Vote Received ===========");
        System.out.println("Ballot      	 : " + ballot);
        System.out.println("Timestamp        : " + timestamp);
        System.out.println("Token            : " + token);
        System.out.println("Signed Token     : " + signedToken);

        ZonedDateTime voteTime = ZonedDateTime.parse(timestamp);
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("Asia/Colombo"));
        long minutesDiff = Duration.between(voteTime, now).toMinutes();

        boolean isTimestampValid = minutesDiff <= 2;
        System.out.println("\nIs vote timestamp within limit? " + isTimestampValid);

        if (!isTimestampValid) {
            System.out.println("Vote rejected: Timestamp expired.");
            return;
        }

        boolean verified = CryptoUtils.verifySHA256withRSA(token.getBytes(),
                Base64.getDecoder().decode(signedToken), getRSAPublicKey());

        System.out.println("Is Signed Token Verified with EA Public Key? " + verified);
        if (!verified) {
            System.out.println("Vote rejected: Invalid token.");
            return;
        }

        saveVoteToCSV(ballot);
        System.out.println("Ballot accepted and stored.");
    }

    private void saveVoteToCSV(String ballotHash) throws IOException {
        try (FileWriter writer = new FileWriter("votes.csv", true)) {
            writer.write(ballotHash + "\n");
        }
    }
    
    public void printVoteSummaryFromCSV() throws Exception {
        System.out.println("\n=========== Voting Summary ===========");

        // Map of candidate names to vote counts
        Map<String, Integer> voteCounts = new LinkedHashMap<>();
        voteCounts.put("A. Alice", 0);
        voteCounts.put("B. Bob", 0);
        voteCounts.put("C. Charlie", 0);
        voteCounts.put("D. David", 0);

        // Precompute hashes for each candidate
        Map<String, String> hashToCandidate = new HashMap<>();
        for (String candidate : voteCounts.keySet()) {
            String hash = CryptoUtils.hashSHA256(candidate);
            hashToCandidate.put(hash, candidate);
        }

        // Read votes.csv and tally votes
        File file = new File("votes.csv");
        if (!file.exists()) {
            System.out.println("No votes were cast in this session.");
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String candidate = hashToCandidate.get(line.trim());
                if (candidate != null) {
                    voteCounts.put(candidate, voteCounts.get(candidate) + 1);
                }
            }
        }

        // Print final result
        for (Map.Entry<String, Integer> entry : voteCounts.entrySet()) {
            System.out.println(entry.getKey() + " - " + entry.getValue() + " vote(s)");
        }
    }

}
