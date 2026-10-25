import java.nio.file.*;
import java.util.*;

public final class LauncherTest {
    public static void main(String[] args) throws Exception {
        String json =
                "{\"options\":{\"ghidraJar\":\"wrong.jar\"},\"array\":[null,true,2.5e2],\"ghidraJar\":\"C:\\\\Program"
                    + " Files\\\\Ghidra\\\\ghidra.jar\",\"label\":\"caf\\u00e9\"}";
        var config = SymbolWeave.parseConfig(json);
        equal("C:\\Program Files\\Ghidra\\ghidra.jar", config.get("ghidraJar"));
        equal("caf" + (char) 0x00e9, config.get("label"));
        for (String invalid :
                List.of(
                        "[]",
                        "{} garbage",
                        "{\"ghidraJar\":\"a\",\"ghidraJar\":\"b\"}",
                        "{\"a\":[1,]}",
                        "{\"a\":01}")) {
            try {
                SymbolWeave.parseConfig(invalid);
                throw new AssertionError("Invalid JSON accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
            }
        }
        equal(
                "A/$value\\folder/z",
                SymbolWeave.expandEnvironment("A/${PATH}/z", Map.of("PATH", "$value\\folder")));
        try {
            SymbolWeave.expandEnvironment("${MISSING}", Map.of());
            throw new AssertionError("Missing variable accepted");
        } catch (IllegalArgumentException expected) {
        }
        Path root = Files.createTempDirectory("symbolweave-launcher-");
        Files.writeString(root.resolve("config.json"), "{}");
        Path nested = Files.createDirectories(root.resolve("nested/deeper"));
        equal(root.resolve("config.json"), SymbolWeave.discover(nested));
        Files.writeString(root.resolve("nested/config.json"), "{}");
        equal(root.resolve("nested/config.json"), SymbolWeave.discover(nested));
        System.out.println(
                "Java launcher config parsing, environment expansion, and discovery passed");
    }

    private static void equal(Object expected, Object actual) {
        if (!Objects.equals(expected, actual))
            throw new AssertionError("Expected " + expected + ", got " + actual);
    }
}
