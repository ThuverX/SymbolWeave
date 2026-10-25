package symbolweave;

import com.google.gson.*;

import symbolweave.containers.*;

import java.nio.file.*;
import java.util.*;

public final class ProjectConfigTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("sdk-config-test-");
        Path config = root.resolve("config.json");
        Files.writeString(
                config,
                "{\"version\":1,\"analyze\":false,\"inputs\":[{\"id\":\"one\",\"xml\":\"data.xml\"}]}");
        Path nested = Files.createDirectories(root.resolve("nested/deeper"));
        equal(config, ProjectConfig.discover(nested));
        ProjectConfig c = ProjectConfig.load(config);
        equal(root.resolve("data.xml"), c.path("data.xml"));
        equal(List.of("one"), c.merge.sources);
        Path closer = root.resolve("nested/config.json");
        Files.copy(config, closer);
        equal(closer, ProjectConfig.discover(nested));
        rejects(config, "{\"version\":2,\"inputs\":[]}", "version");
        rejects(config, "{\"version\":1,\"typo\":true}", "$.typo");
        rejects(config, "{\"version\":1,\"analyze\":\"false\"}", "boolean");
        rejects(
                config,
                "{\"version\":1,\"inputs\":[{\"id\":\"a\",\"xml\":\"a\",\"typo\":true}]}",
                "$.inputs[0].typo");
        rejects(
                config,
                "{\"version\":1,\"inputs\":[{\"id\":\"a\",\"xml\":\"a\"},{\"id\":\"a\",\"xml\":\"b\"}]}",
                "duplicate");
        rejects(
                config,
                "{\"version\":1,\"inputs\":[{\"id\":\"a\",\"xml\":\"a\"}],\"merge\":{\"sources\":[\"missing\"]}}",
                "Unknown input");
        System.out.println("Config discovery, relative paths, and validation passed");
    }

    private static void rejects(Path file, String json, String contains) throws Exception {
        Files.writeString(file, json);
        try {
            ProjectConfig.load(file);
            throw new AssertionError("Accepted invalid config");
        } catch (IllegalArgumentException e) {
            if (!e.getMessage().contains(contains)) throw new AssertionError(e);
        }
    }

    static void equal(Object expected, Object actual) {
        if (!Objects.equals(expected, actual))
            throw new AssertionError("Expected " + expected + ", got " + actual);
    }
}
