package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.MemberContainer;
import symbolweave.containers.TypeContainer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

public final class MemberSupportTest {
    public static void main(String[] args) throws Exception {
        xmlRoundTripPreservesLayoutMetadata();
        xmlRoundTripPreservesFunctionAnalysisMetadata();
        onlyPatchMembersAreMerged();
        writerEmitsPaddingAndAddressedMembers();
        packedBaseTailPreservesDerivedOffsets();
        overlappingMembersAreRejected();
    }

    private static void xmlRoundTripPreservesFunctionAnalysisMetadata() throws Exception {
        ClassContainer example = cls("AbstractExample");
        example.setVtableCount(1);
        FunctionContainer function =
                new FunctionContainer(Util.NamespacedString.parse("AbstractExample::Run"));
        function.setAddress(0x140001000L);
        function.setImplementationAddress(0x140002000L);
        function.setPureVirtual(true);
        example.getVirtualFunctions().put(0, function);

        Path xml = Files.createTempFile("symbolweave-functions-", ".xml");
        try {
            DataXMLSerializer.writeContainerToFile(file(example), xml);
            String serialized = Files.readString(xml);
            assertContains(serialized, "isPureVirtual=\"true\"");
            FunctionContainer restored =
                    DataXMLSerializer.readContainerFromFile(xml)
                            .getClasses()
                            .getFirst()
                            .getVirtualFunctions()
                            .get(0);
            assertEquals(true, restored.isPureVirtual());
            assertEquals(true, restored.hasPureVirtualValue());
            assertEquals(0x140002000L, restored.getImplementationAddress());
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    private static void xmlRoundTripPreservesLayoutMetadata() throws Exception {
        FileContainer source = file(cls("Example"));
        source.getClasses()
                .getFirst()
                .getMembers()
                .add(instance("mValue", "std::uint32_t", 4, 0x18));
        source.getClasses()
                .getFirst()
                .getMembers()
                .add(addressed("sValue", "float", 4, 0x140001000L, true));

        Path xml = Files.createTempFile("symbolweave-members-", ".xml");
        try {
            DataXMLSerializer.writeContainerToFile(source, xml);
            FileContainer restored = DataXMLSerializer.readContainerFromFile(xml);
            MemberContainer instance = restored.getClasses().getFirst().getMembers().get(0);
            MemberContainer addressed = restored.getClasses().getFirst().getMembers().get(1);
            assertEquals(4L, instance.getSize());
            assertEquals(0x18L, instance.getOffset());
            assertEquals(0x140001000L, addressed.getAddress());
            assertEquals(true, addressed.getType().isConst());
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    private static void onlyPatchMembersAreMerged() {
        ClassContainer pcClass = cls("Example");
        ClassContainer firstPatchClass = cls("Example");
        firstPatchClass.getMembers().add(instance("manual", "int", 4, 8));
        ClassContainer secondPatchClass = cls("Example");
        secondPatchClass.getMembers().add(instance("manual", "float", 4, 8));
        secondPatchClass.getMembers().add(instance("manual2", "int", 4, 12));

        FileContainer merged =
                ConfigurableMerger.merge(
                        List.of(file(pcClass), file(firstPatchClass), file(secondPatchClass)));
        List<MemberContainer> members = merged.getClasses().getFirst().getMembers();
        assertEquals(2, members.size());
        assertEquals("manual", members.get(0).getName());
        assertEquals("float", members.get(0).getType().getName().toString());
        assertEquals("manual2", members.get(1).getName());
    }

    private static void writerEmitsPaddingAndAddressedMembers() throws Exception {
        ClassContainer example = cls("Example");
        example.setVtableCount(1);
        example.getMembers().add(instance("mFirst", "std::uint32_t", 4, 0x10));
        example.getMembers().add(instance("mSecond", "std::uint64_t", 8, 0x18));
        example.getMembers().add(addressed("sValue", "float", 4, 0x140001000L, true));
        MemberContainer array = addressed("sValues", "float", 12, 0x140001010L, true);
        array.getType().setSuffix("[3]");
        example.getMembers().add(array);
        FileContainer source = file(example);

        Path output = Files.createTempDirectory("symbolweave-member-writer-");
        try {
            SDKWriter.writeToDirectory(source, output);
            String header = Files.readString(output.resolve("Example.h"));
            assertContains(header, "#pragma pack(push, 1)");
            assertBefore(header, "#pragma pack(push, 1)", "class Example");
            assertContains(header, "std::byte _pad_0008[0x8];");
            assertContains(header, "std::uint32_t mFirst;");
            assertContains(header, "std::byte _pad_0014[0x4];");
            assertContains(header, "SDK_ADDRESS_MEMBER((const float), sValue, 0x140001000);");
            assertContains(
                    header,
                    "static auto sValues() -> const float (&)[3] { return *reinterpret_cast<const"
                            + " float (*)[3]>(SDK_REBASE_ADDRESS(0x140001010)); }");
            assertContains(
                    Files.readString(output.resolve("SdkMetadata.h")),
                    "static SDK_DETAIL_UNPAREN Type& Name()");
            assertContains(header, "static_assert(offsetof(Example, mSecond) == 0x18);");
            assertContains(header, "static_assert(sizeof(decltype(Example::mSecond)) == 0x8);");
            assertContains(header, "#pragma pack(pop)");
            assertBefore(header, "};", "#pragma pack(pop)");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void packedBaseTailPreservesDerivedOffsets() throws Exception {
        ClassContainer base = cls("PackedBase");
        base.setVtableCount(1);
        base.getMembers().add(instance("mCount", "std::uint8_t", 1, 0x10));
        ClassContainer derived = cls("PackedDerived");
        derived.getParents().add(base.getName());
        derived.getMembers().add(instance("mValue", "std::uint32_t", 4, 0x20));

        Path output = Files.createTempDirectory("symbolweave-packed-base-");
        try {
            SDKWriter.writeToDirectory(file(base, derived), output);
            String header = Files.readString(output.resolve("PackedDerived.h"));
            assertContains(header, "std::byte _pad_0011[0xF];");
            assertContains(header, "static_assert(offsetof(PackedDerived, mValue) == 0x20);");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void overlappingMembersAreRejected() {
        ClassContainer example = cls("Example");
        example.getMembers().add(instance("first", "std::uint64_t", 8, 0));
        example.getMembers().add(instance("second", "std::uint32_t", 4, 4));
        try {
            SDKWriter.validateMembers(file(example));
            throw new AssertionError("Expected overlapping members to be rejected");
        } catch (IllegalArgumentException expected) {
            assertContains(expected.getMessage(), "overlaps layout");
        }
    }

    private static MemberContainer instance(String name, String typeName, long size, long offset) {
        MemberContainer member = new MemberContainer(name);
        member.setType(new TypeContainer(Util.NamespacedString.parse(typeName)));
        member.setSize(size);
        member.setOffset(offset);
        return member;
    }

    private static MemberContainer addressed(
            String name, String typeName, long size, long address, boolean isConst) {
        MemberContainer member = new MemberContainer(name);
        member.setType(new TypeContainer(Util.NamespacedString.parse(typeName), "", "", isConst));
        member.setSize(size);
        member.setAddress(address);
        member.setStatic(true);
        return member;
    }

    private static ClassContainer cls(String name) {
        return new ClassContainer(
                Util.NamespacedString.parse(name),
                0,
                0,
                new HashMap<>(),
                new ArrayList<>(),
                new ArrayList<>(),
                new ArrayList<>());
    }

    private static FileContainer file(ClassContainer... classes) {
        FileContainer file = new FileContainer("test");
        file.getClasses().addAll(List.of(classes));
        return file;
    }

    private static void assertContains(String text, String expected) {
        if (!text.contains(expected)) throw new AssertionError("Missing text: " + expected);
    }

    private static void assertBefore(String text, String first, String second) {
        int firstIndex = text.indexOf(first);
        int secondIndex = text.indexOf(second);
        if (firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex) {
            throw new AssertionError("Expected " + first + " before " + second);
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + " but got " + actual);
        }
    }
}
