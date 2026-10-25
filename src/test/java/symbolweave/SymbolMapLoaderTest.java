package symbolweave;

import com.google.gson.*;

import java.nio.file.*;

public final class SymbolMapLoaderTest {
    public static ghidra.app.util.demangler.DemangledObject demangleSymbol(String symbol) {
        return null;
    }

    public static void main(String[] args) throws Exception {
        Path file = Files.createTempFile("sdk-map-", ".map");
        Files.writeString(
                file,
                "ignored header\nSYMBOL 4096 20 Alpha engine.o\nSYMBOL 8192 40 Beta renderer.o\n");
        JsonObject options =
                JsonParser.parseString(
                                "{\"file\":\"unused\",\"lineFilter\":\"SYMBOL"
                                    + " .*\",\"lineRegex\":\"SYMBOL (?<Address>[0-9]+)"
                                    + " (?<Size>[0-9]+) (?<Name>[^ ]+) (?<Unit>[^"
                                    + " ]+)\",\"fields\":{\"address\":\"Address\",\"size\":\"Size\",\"name\":\"Name\",\"unit\":\"Unit\"},\"radix\":10,\"demanglerClass\":\"symbolweave.SymbolMapLoaderTest\",\"vtableRegex\":\"^VT_\"}")
                        .getAsJsonObject();
        var parsed = new SymbolMapLoader(file, options);
        ProjectConfigTest.equal(2, parsed.entries().size());
        ProjectConfigTest.equal(4096L, parsed.entries().getFirst().address);
        ProjectConfigTest.equal(20L, parsed.entries().getFirst().size);
        ProjectConfigTest.equal("Alpha", parsed.entries().getFirst().name);
        ProjectConfigTest.equal("engine.o", parsed.entries().getFirst().unit);
        Files.writeString(file, "SYMBOL malformed\n");
        try {
            new SymbolMapLoader(file, options);
            throw new AssertionError("Malformed line accepted");
        } catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(":1:")) throw new AssertionError(expected);
        }
        options.addProperty("malformed", "skip");
        ProjectConfigTest.equal(0, new SymbolMapLoader(file, options).entries().size());
        System.out.println(
                "Configurable map dialect, numeric bases, and malformed-line handling passed");
    }
}
