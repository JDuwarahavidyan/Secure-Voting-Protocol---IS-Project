import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class VotingSession {
    private final Scanner scanner = new Scanner(System.in);
    private final AuthService authService = new AuthService();
    public VotingSession(Authority authority) {
    }

    public void run() throws Exception {
        System.out.println("=========== Authentication Phase ==========");
        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        String nonce = Nonce.generateNonce();
        System.out.println("Generated nonce: " + nonce);

        String clientHash = CryptoUtils.hashSHA256(password + nonce);
        System.out.println("Client Hash (pw + nonce): " + clientHash);
        boolean authenticated = authService.authenticate(username, nonce, clientHash);

        if (!authenticated) {
            System.out.println("Authentication failed.");
            return;
        }

        System.out.println("Authentication successful!");
        

        Authority authority = new Authority();
        Voter voter = new Voter();
        
        if (authority.hasUserReceivedSignedToken(username)) {
            System.out.println("\nAccess Denied: Each user is allowed to vote only once.");
            return;
        }

        PublicKey eaDHPubKey = authority.getDHPublicKey();
        String eaCert = authority.getCertificate();

        System.out.println("\n=========== EA sends to Voter ===========");
        System.out.println("Requsting a Token");
        System.out.println("EA DH Public Key (g^a mod p): " + Base64.getEncoder().encodeToString(eaDHPubKey.getEncoded()));
        System.out.println("EA Certificate: " + eaCert);

        System.out.println("\n=========== Voter Preparing the Token ===========");
        PublicKey eaRSAPubKey;
        try {
            eaRSAPubKey = CryptoUtils.decodeRSAPublicKey(eaCert);
            System.out.println("Is EA Certificate Valid? true");
        } catch (Exception e) {
            System.out.println("Is EA Certificate Valid? false");
            return;
        }

        PublicKey voterDHPubKey = voter.getVoterDHPublicKey();
        String token = voter.issueToken();
        System.out.println("Voter Token: " + token);

        var sharedKey = CryptoUtils.deriveSharedSecret(voter.getVoterDHPrivateKey(), eaDHPubKey);
        byte[] encryptedToken = CryptoUtils.encryptWithSharedSecret(token.getBytes(), sharedKey);
        String encryptedTokenBase64 = Base64.getEncoder().encodeToString(encryptedToken);
        String sessionKeyBase64 = Base64.getEncoder().encodeToString(sharedKey.getEncoded());

        System.out.println("\n=========== Voter sends to EA ===========");
        System.out.println("Voter DH Public Key (g^b mod p): " + Base64.getEncoder().encodeToString(voterDHPubKey.getEncoded()));
        System.out.println("Session Key (g^ab mod p): " + sessionKeyBase64);
        System.out.println("Encrypted Token: " + encryptedTokenBase64);

        

        String encryptedSignedTokenBase64 = authority.respondToTokenRequest(username, token, voterDHPubKey);
        if (encryptedSignedTokenBase64 == null) return;

        System.out.println("\n=========== EA responds ===========");
        System.out.println("Encrypted Signed Token: " + encryptedSignedTokenBase64);

        byte[] encryptedSignedBytes = Base64.getDecoder().decode(encryptedSignedTokenBase64);
        byte[] signedTokenBytes = CryptoUtils.decryptWithSharedSecret(encryptedSignedBytes, sharedKey);
        String signedTokenBase64 = new String(signedTokenBytes);

        System.out.println("\n=========== Voter Receives ===========");
        System.out.println("Signed Token: " + signedTokenBase64);

        boolean verified = CryptoUtils.verifySHA256withRSA(token.getBytes(),
                Base64.getDecoder().decode(signedTokenBase64), eaRSAPubKey);
        System.out.println("Is Signed Token Verified with EA Public Key? " + verified);

        if (!verified) {
            System.out.println("Token signature verification failed.");
            return;
        }

        System.out.println("\n=========== Voting Phase ===========");
        System.out.println("Available candidates: ");
        for (String candidate : Candidate.getCandidates()) {
            System.out.println(candidate);
        }

        String vote;
        while (true) {
            System.out.print("Enter your vote (A, B, C, D) or Q to quit: ");
            vote = scanner.nextLine().toUpperCase();

            if (vote.equals("Q")) {
                System.out.println("Exiting voting.");
                return;
            }

            if (Candidate.isValidChoice(vote)) {
                String candidateName = Candidate.getCandidateName(vote);
                System.out.println("Preparing your vote..." + vote);
                System.out.println("Preparing your vote...");

                String encryptedPayload = voter.prepareEncryptedVote(candidateName, token, signedTokenBase64, eaRSAPubKey);
                authority.processVote(encryptedPayload);
                return;
            } else {
                System.out.println("Invalid vote. Try again.");
            }
        }
    }
}
