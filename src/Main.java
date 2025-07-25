import java.time.Duration;
import java.time.Instant;

public class Main {
    public static void main(String[] args) throws Exception {
        Instant sessionStart = Instant.now();
        Duration sessionLimit = Duration.ofMinutes(1);

        Authority authority = new Authority(); 

        System.out.println("Voting session started. You have 5 minutes.\n");

        while (true) {
            Duration elapsed = Duration.between(sessionStart, Instant.now());

            if (elapsed.compareTo(sessionLimit) >= 0) {
                System.out.println("Voting session has expired. Logging out...");
                authority.printVoteSummaryFromCSV(); 
                break;
            }

            VotingSession session = new VotingSession(authority);  // Pass the same authority instance
            session.run();

            System.out.println("\nReturning to login screen...\n");
        }
    }
}
