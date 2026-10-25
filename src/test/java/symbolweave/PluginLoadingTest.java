package symbolweave;

import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

import javax.tools.ToolProvider;

public final class PluginLoadingTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("sdk-plugin-");
        Path source = root.resolve("MarkerPlugin.java");
        Files.writeString(
                source,
                "public class MarkerPlugin implements symbolweave.SdkPlugin { public String"
                    + " name(){return \"marker\";} public void match(symbolweave.ProjectConfig c,"
                    + " symbolweave.ProjectConfig.Match r,"
                    + " java.util.Map<String,symbolweave.containers.FileContainer> files)throws"
                    + " Exception"
                    + " {java.nio.file.Files.writeString(c.path(\"plugin-ran.txt\"),\"executed\");}"
                    + " }");
        int status =
                ToolProvider.getSystemJavaCompiler()
                        .run(
                                null,
                                null,
                                null,
                                "--release",
                                "21",
                                "-cp",
                                System.getProperty("java.class.path"),
                                "-d",
                                root.toString(),
                                source.toString());
        if (status != 0) throw new AssertionError("Plugin compilation failed");
        Path jar = root.resolve("plugin.jar");
        try (var out = new JarOutputStream(Files.newOutputStream(jar))) {
            out.putNextEntry(new JarEntry("MarkerPlugin.class"));
            out.write(Files.readAllBytes(root.resolve("MarkerPlugin.class")));
            out.closeEntry();
            out.putNextEntry(new JarEntry("META-INF/services/symbolweave.SdkPlugin"));
            out.write("MarkerPlugin\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.closeEntry();
        }
        Files.writeString(root.resolve("input.xml"), "<Data/>");
        Files.writeString(
                root.resolve("config.json"),
                "{\"version\":1,\"analyze\":false,\"pluginJars\":[\"plugin.jar\"],\"inputs\":[{\"id\":\"a\",\"xml\":\"input.xml\"}],\"matching\":[{\"source\":\"a\",\"target\":\"a\",\"plugin\":\"marker\"}],\"outputs\":{\"supportHeaders\":[]}}");
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        if (!Files.readString(root.resolve("plugin-ran.txt")).equals("executed"))
            throw new AssertionError("Provider did not execute");
        System.out.println("External plugin JAR discovery and execution passed");
    }
}
