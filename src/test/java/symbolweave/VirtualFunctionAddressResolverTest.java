package symbolweave;

import symbolweave.containers.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.List;

public final class VirtualFunctionAddressResolverTest {
    public static void main(String[] args) throws Exception {
        for (int pointerSize : List.of(4, 8)) {
            resolvePointers(pointerSize);
            pipeline(pointerSize);
        }
        invalidConfiguration();
        System.out.println("Per-layer vtable resolution, PE32/PE32+, and patch precedence passed");
    }

    // The section is mapped at RVA 0x2000 but stored at file offset 0x200.
    // This catches accidental reads at virtual-address or RVA file offsets.
    static Path image(Path root, int pointerSize) throws Exception {
        byte[] data = new byte[0x400];
        ByteBuffer bytes = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putShort(0, (short) 0x5A4D);
        bytes.putInt(0x3C, 0x80);
        bytes.putInt(0x80, 0x4550);
        bytes.putShort(0x84, (short) (pointerSize == 4 ? 0x14C : 0x8664));
        bytes.putShort(0x86, (short) 1);
        int optional = 0x98;
        int optionalSize = pointerSize == 4 ? 0xE0 : 0xF0;
        bytes.putShort(0x94, (short) optionalSize);
        bytes.putShort(optional, (short) (pointerSize == 4 ? 0x10B : 0x20B));
        long base = base(pointerSize);
        if (pointerSize == 4) bytes.putInt(optional + 28, (int) base);
        else bytes.putLong(optional + 24, base);
        bytes.putInt(optional + 56, 0x3000);
        bytes.putInt(optional + 60, 0x200);
        int section = optional + optionalSize;
        bytes.putInt(section + 8, 0x300); // Virtual tail is not file-backed.
        bytes.putInt(section + 12, 0x2000);
        bytes.putInt(section + 16, 0x200);
        bytes.putInt(section + 20, 0x200);
        for (int index = 0; index < 4; index++) {
            long target = index == 3 ? 0 : base + 0x1000 + index * 0x10;
            if (pointerSize == 4) bytes.putInt(0x200 + index * pointerSize, (int) target);
            else bytes.putLong(0x200 + index * pointerSize, target);
        }
        Path path = root.resolve("fixture.exe");
        Files.write(path, data);
        return path;
    }

    static long base(int pointerSize) {
        return pointerSize == 4 ? 0xF0000000L : 0x140000000L;
    }

    static FunctionContainer fn(String name) {
        return new FunctionContainer(Util.NamespacedString.parse(name));
    }

    static void resolvePointers(int pointerSize) throws Exception {
        Path root = Files.createTempDirectory("sdk-pointer-test-");
        Path path = image(root, pointerSize);
        PortableExecutable pe = PortableExecutable.readImage(path);
        ProjectConfigTest.equal(pointerSize, pe.pointerSize());
        if (pointerSize == 8)
            ProjectConfigTest.equal(8, PortableExecutable.read(path).pointerSize());
        else {
            try {
                PortableExecutable.read(path);
                throw new AssertionError("32-bit PE must not enable the x64 signature decoder");
            } catch (IOException expected) {
                ProjectConfigTest.equal(true, expected.getMessage().contains("AMD64"));
            }
        }
        long vtable = base(pointerSize) + 0x2000;
        var file = new FileContainer("test");
        var cls = new ClassContainer(Util.NamespacedString.parse("C"));
        cls.setVtableAddress(vtable);
        cls.setVtableCount(4);
        file.getClasses().add(cls);
        for (int slot = 0; slot < 4; slot++) cls.getVirtualFunctions().put(slot, fn("C::F" + slot));
        // A supplied implementation must remain entirely untouched, even if address is missing.
        cls.getVirtualFunctions().get(2).setImplementationAddress(0x1234);
        cls.getVirtualFunctions().put(4, null);
        var regular = fn("C::Regular");
        cls.getFunctions().add(regular);
        var loose = fn("Loose");
        file.getLooseFunctions().add(loose);
        var result = VirtualFunctionAddressResolver.resolve(file, pe);
        ProjectConfigTest.equal(3, result.slots());
        ProjectConfigTest.equal(2, result.implementations());
        ProjectConfigTest.equal(0, result.unreadable());
        ProjectConfigTest.equal(
                vtable + pointerSize, cls.getVirtualFunctions().get(1).getAddress());
        ProjectConfigTest.equal(
                base(pointerSize) + 0x1010,
                cls.getVirtualFunctions().get(1).getImplementationAddress());
        ProjectConfigTest.equal(
                0x1234L, cls.getVirtualFunctions().get(2).getImplementationAddress());
        ProjectConfigTest.equal(0L, cls.getVirtualFunctions().get(2).getAddress());
        ProjectConfigTest.equal(0L, cls.getVirtualFunctions().get(3).getImplementationAddress());
        ProjectConfigTest.equal(0L, regular.getAddress());
        ProjectConfigTest.equal(0L, loose.getAddress());
        // Explicit physical slot addresses take priority over a logical index.
        var secondary = fn("C::Secondary");
        secondary.setAddress(vtable + pointerSize);
        secondary.setVtableOwner(Util.NamespacedString.parse("Base"));
        cls.getVirtualFunctions().put(5, secondary);
        // Inferred secondary addresses must not use the primary vtable base.
        var unknownSecondary = fn("C::UnknownSecondary");
        unknownSecondary.setVtableOwner(Util.NamespacedString.parse("Base"));
        cls.getVirtualFunctions().put(6, unknownSecondary);
        var invalid = fn("C::Invalid");
        invalid.setAddress(vtable + 0x200 - pointerSize + 1);
        cls.getVirtualFunctions().put(7, invalid);
        result = VirtualFunctionAddressResolver.resolve(file, pe);
        ProjectConfigTest.equal(1, result.implementations());
        ProjectConfigTest.equal(1, result.unreadable());
        ProjectConfigTest.equal(base(pointerSize) + 0x1010, secondary.getImplementationAddress());
        ProjectConfigTest.equal(0L, unknownSecondary.getAddress());
        ProjectConfigTest.equal(0L, invalid.getImplementationAddress());
        try {
            pe.readPointerAtVa(vtable + 0x200);
            throw new AssertionError("Must reject virtual-only section bytes");
        } catch (IOException expected) {
            ProjectConfigTest.equal(true, expected.getMessage().contains("unmapped"));
        }
    }

    static void pipeline(int pointerSize) throws Exception {
        Path root = Files.createTempDirectory("sdk-resolve-pipeline-");
        image(root, pointerSize);
        long vtable = base(pointerSize) + 0x2000;
        Files.writeString(
                root.resolve("symbols.xml"),
                """
                <Data><Classes><Class name="C" vtableCount="3"><Functions>
                <VirtualFunction index="0" name="C::Run"/>
                <VirtualFunction index="1" name="C::Patched"/>
                <VirtualFunction index="2" name="C::Known" implementationAddress="0x1234"/>
                </Functions></Class></Classes></Data>
                """);
        Files.writeString(root.resolve("pc.xml"), "<Data/>");
        Files.writeString(
                root.resolve("patch.xml"),
                """
                <Data><Classes><Class name="C" address="%s"><Functions>
                <VirtualFunction index="1" implementationAddress="0x5678"/>
                </Functions></Class></Classes></Data>
                """
                        .formatted("0x" + Long.toHexString(vtable)));
        // First resolve after the source, then after a patch supplies the vtable.
        String configuration =
                """
                {"version":1,"analyze":false,"inputs":[
                 {"id":"symbols","xml":"symbols.xml"},
                 {"id":"pc","xml":"pc.xml","executable":"fixture.exe"}],
                 "merge":{"sources":["symbols"],
                  "sourcePolicies":{"symbols":{"resolveVirtualFunctionAddressesFrom":"pc"}},
                  "patches":[{"files":["patch.xml"],"headerFromFilename":false,
                    "policy":{"resolveVirtualFunctionAddressesFrom":"pc"}}]},
                 "outputs":{"xml":"merged.xml","headers":"headers"}}
                """;
        Files.writeString(root.resolve("config.json"), configuration);
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        var cls =
                DataXMLSerializer.readContainerFromFile(root.resolve("merged.xml"))
                        .getClasses()
                        .getFirst();
        ProjectConfigTest.equal(vtable, cls.getVirtualFunctions().get(0).getAddress());
        ProjectConfigTest.equal(
                base(pointerSize) + 0x1000,
                cls.getVirtualFunctions().get(0).getImplementationAddress());
        ProjectConfigTest.equal(
                0x5678L, cls.getVirtualFunctions().get(1).getImplementationAddress());
        ProjectConfigTest.equal(
                0x1234L, cls.getVirtualFunctions().get(2).getImplementationAddress());
        String header = Files.readString(root.resolve("headers/C.h"));
        ProjectConfigTest.equal(
                true,
                header.contains("0x" + Long.toHexString(base(pointerSize) + 0x1000).toUpperCase()));
        // A source with a known vtable resolves without a patch or an output executable setting.
        Files.writeString(
                root.resolve("symbols.xml"),
                Files.readString(root.resolve("symbols.xml"))
                        .replace(
                                "name=\"C\"",
                                "name=\"C\" address=\"0x" + Long.toHexString(vtable) + "\""));
        var json = com.google.gson.JsonParser.parseString(configuration).getAsJsonObject();
        json.getAsJsonObject("merge").remove("patches");
        Files.writeString(root.resolve("config.json"), json.toString());
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        cls =
                DataXMLSerializer.readContainerFromFile(root.resolve("merged.xml"))
                        .getClasses()
                        .getFirst();
        ProjectConfigTest.equal(
                base(pointerSize) + 0x1010,
                cls.getVirtualFunctions().get(1).getImplementationAddress());
        // Default disabled means no binary access and no resolution.
        json.getAsJsonObject("merge").remove("sourcePolicies");
        Files.delete(root.resolve("fixture.exe"));
        Files.writeString(root.resolve("config.json"), json.toString());
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        cls =
                DataXMLSerializer.readContainerFromFile(root.resolve("merged.xml"))
                        .getClasses()
                        .getFirst();
        ProjectConfigTest.equal(0L, cls.getVirtualFunctions().get(0).getImplementationAddress());
    }

    static void invalidConfiguration() throws Exception {
        Path root = Files.createTempDirectory("sdk-resolve-config-");
        String config =
                """
                {"version":1,"inputs":[{"id":"a","xml":"a.xml"}],
                "merge":{"sourcePolicies":{"a":{"resolveVirtualFunctionAddressesFrom":"%s"}}}}
                """;
        for (String input : List.of("missing", "a")) {
            Path path = root.resolve("config.json");
            Files.writeString(path, config.formatted(input));
            try {
                ProjectConfig.load(path);
                throw new AssertionError("Accepted missing executable source " + input);
            } catch (IllegalArgumentException expected) {
                ProjectConfigTest.equal(true, expected.getMessage().contains(input));
            }
        }
    }
}
