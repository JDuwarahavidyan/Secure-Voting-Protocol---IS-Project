import java.util.HashMap;
import java.util.Map;

public class VoterDB {

    // In-memory voter DB
    private static final Map<String, String> voterMap = new HashMap<>();

    static {
        voterMap.put("duwarahan", "123");
        voterMap.put("vidyan", "123");
        voterMap.put("sachi", "456");
        voterMap.put("tharuka", "789");
    }

    public static boolean isValidUser(String username) {
        return voterMap.containsKey(username);
    }

    public static String getPassword(String username) {
        return voterMap.get(username);
    }
}
