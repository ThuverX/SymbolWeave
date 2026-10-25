package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.TypeContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

public final class SDKWriterSecondaryVtableTest {
    public static void main(String[] args) throws IOException {
        varargsFunctionsIncludeEllipsisInDeclarationAndMetadata();
        primarySlotsUseImplementationIdentityAndParentSignature();
        pureVirtualsGenerateAbstractBasesAndConcreteOverrides();
        concreteVirtualsHaveInlineImplementations();
        classStaticFunctionsHaveInlineImplementations();
        namespaceStaticFunctionsDeclareMetadataFirst();
        secondaryVtableUsesPhysicalParentReceiver();
    }

    private static void varargsFunctionsIncludeEllipsisInDeclarationAndMetadata()
            throws IOException {
        FunctionContainer function = function("LogMessage", false);
        function.setVarargs(true);
        function.getParameters()
                .put(
                        0,
                        new symbolweave.containers.ParameterContainer(
                                "level",
                                new TypeContainer(Util.NamespacedString.parse("std::uint32_t"))));
        function.getParameters()
                .put(
                        1,
                        new symbolweave.containers.ParameterContainer(
                                "filename",
                                new TypeContainer(
                                        Util.NamespacedString.parse("char"), "", "*", true)));
        function.getParameters()
                .put(
                        2,
                        new symbolweave.containers.ParameterContainer(
                                "line_number",
                                new TypeContainer(Util.NamespacedString.parse("int"))));
        function.getParameters()
                .put(
                        3,
                        new symbolweave.containers.ParameterContainer(
                                "message",
                                new TypeContainer(
                                        Util.NamespacedString.parse("char"), "", "*", true)));

        FileContainer source = new FileContainer("test");
        source.getLooseFunctions().add(function);
        Path output = Files.createTempDirectory("symbolweave-varargs-test-");
        try {
            SDKWriter.writeToDirectory(source, output);
            String header = Files.readString(output.resolve("Global.h"));
            assertContains(
                    header,
                    "SDK_DIRECT_FUNCTION(LogMessageMetadata, void, LogMessage, 0x0, "
                            + "(void (*)(std::uint32_t, const char*, int, const char*, ...)))");
            assertContains(
                    header,
                    "template <typename... TArgs>\n"
                        + "inline void LogMessage(std::uint32_t level, const char* filename, int"
                        + " line_number, const char* message, TArgs&&... args)");
            assertContains(
                    header,
                    "SDK_STATIC_IMPLEMENTATION(LogMessageMetadata,level, filename, line_number,"
                            + " message, static_cast<TArgs&&>(args)...)");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void namespaceStaticFunctionsDeclareMetadataFirst() throws IOException {
        ClassContainer namespace = cls("ExampleNamespace", 0, List.of());
        FunctionContainer function = function("ExampleNamespace::GetValue", false);
        function.setStatic(true);
        namespace.getFunctions().add(function);

        FileContainer source = new FileContainer("test");
        source.getClasses().add(namespace);
        Path output = Files.createTempDirectory("symbolweave-namespace-static-test-");
        try {
            SDKWriter.writeToDirectory(source, output);
            String header = Files.readString(output.resolve("ExampleNamespace.h"));
            assertBefore(header, "SDK_DIRECT_FUNCTION(GetValueMetadata", "static void GetValue()");
            assertDoesNotContain(header, "struct GetValueMetadata;");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void classStaticFunctionsHaveInlineImplementations() throws IOException {
        ClassContainer owner = cls("StaticOwner", 1, List.of());
        FunctionContainer pure = function("StaticOwner::Run", false);
        pure.setPureVirtual(true);
        owner.getVirtualFunctions().put(0, pure);
        FunctionContainer noArguments = function("StaticOwner::Reset", false);
        noArguments.setStatic(true);
        owner.getFunctions().add(noArguments);
        FunctionContainer withArgument = function("StaticOwner::SetValue", false);
        withArgument.setStatic(true);
        withArgument
                .getParameters()
                .put(
                        0,
                        new symbolweave.containers.ParameterContainer(
                                "value", new TypeContainer(Util.NamespacedString.parse("long"))));
        owner.getFunctions().add(withArgument);

        FileContainer source = new FileContainer("test");
        source.getClasses().add(owner);
        Path output = Files.createTempDirectory("symbolweave-inline-static-member-test-");
        try {
            SDKWriter.writeToDirectory(source, output);
            String header = Files.readString(output.resolve("StaticOwner.h"));
            assertBefore(header, "SDK_DIRECT_FUNCTION(ResetMetadata", "static void Reset()");
            assertBefore(header, "SDK_DIRECT_FUNCTION(SetValueMetadata", "static void SetValue(");
            assertDoesNotContain(header, "struct ResetMetadata;");
            assertDoesNotContain(header, "struct SetValueMetadata;");
            assertContains(
                    header, "static void Reset() { SDK_STATIC_IMPLEMENTATION(ResetMetadata); }");
            assertContains(
                    header,
                    "static void SetValue(long value) { SDK_STATIC_IMPLEMENTATION(SetValueMetadata,"
                            + " value); }");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void concreteVirtualsHaveInlineImplementations() throws IOException {
        ClassContainer concrete = cls("ConcreteBase", 2, List.of());
        concrete.getVirtualFunctions().put(0, function("ConcreteBase::~ConcreteBase", false));
        FunctionContainer query = function("ConcreteBase::Query", false);
        query.setReturnType(new TypeContainer(Util.NamespacedString.parse("bool")));
        query.getParameters()
                .put(
                        0,
                        new symbolweave.containers.ParameterContainer(
                                "value", new TypeContainer(Util.NamespacedString.parse("long"))));
        concrete.getVirtualFunctions().put(1, query);

        FileContainer source = new FileContainer("test");
        source.getClasses().add(concrete);
        Path output = Files.createTempDirectory("symbolweave-inline-virtual-test-");
        try {
            SDKWriter.writeToDirectory(SDKWriter.collapseContainer(source), output);
            String header = Files.readString(output.resolve("ConcreteBase.h"));
            assertBefore(header, "SDK_VIRTUAL_FUNCTION(QueryMetadata", "virtual bool Query(");
            assertDoesNotContain(header, "struct QueryMetadata;");
            assertContains(header, "virtual ~ConcreteBase() = default;");
            assertContains(
                    header,
                    "virtual bool Query(long value) { SDK_VIRTUAL_IMPLEMENTATION(QueryMetadata,"
                            + " this, value); }");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void secondaryVtableUsesPhysicalParentReceiver() throws IOException {
        ClassContainer resourceInterface = cls("Example::IResourceSystem", 15, List.of());
        ClassContainer manager = cls("Example::Manager", 41, List.of());
        ClassContainer resourceSystem =
                cls(
                        "Example::ResourceSystem",
                        15,
                        List.of(resourceInterface.getName(), manager.getName()));
        resourceSystem
                .getVirtualFunctions()
                .put(32, function("Example::ResourceSystem::FindDatabase", true));

        FileContainer source = new FileContainer("test");
        source.getClasses().addAll(List.of(resourceInterface, manager, resourceSystem));
        FunctionContainer directFunction = function("DirectFunction", false);
        directFunction.setStatic(true);
        source.getLooseFunctions().add(directFunction);

        Path output = Files.createTempDirectory("symbolweave-writer-test-");
        try {
            SDKWriter.writeToDirectory(SDKWriter.collapseContainer(source), output);
            String header = Files.readString(output.resolve("Example/ResourceSystem.h"));
            String globalHeader = Files.readString(output.resolve("Global.h"));
            assertContains(
                    header,
                    "SDK_VIRTUAL_FUNCTION(FindDatabase_OverrideMetadata, ResourceSystem,"
                            + " FindDatabase_Override, 0x0, 32, ( void (*)(Example::Manager*)))");
            assertDoesNotContain(
                    header, "FindDatabase_Override, 0x0, 32, ( void (*)(ResourceSystem*))");
            assertContains(globalHeader, "SDK_DIRECT_FUNCTION(DirectFunctionMetadata");
            assertDoesNotContain(globalHeader, "SDK_FUNCTION(");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void primarySlotsUseImplementationIdentityAndParentSignature() {
        ClassContainer parent = cls("Parent", 2, List.of());
        FunctionContainer unchangedParent = function("Parent::Unchanged", false);
        unchangedParent.setImplementationAddress(0x1000);
        parent.getVirtualFunctions().put(0, unchangedParent);
        FunctionContainer replacedParent = function("Parent::ParentName", false);
        replacedParent.setImplementationAddress(0x2000);
        replacedParent.setReturnType(new TypeContainer(Util.NamespacedString.parse("bool")));
        parent.getVirtualFunctions().put(1, replacedParent);

        ClassContainer child = cls("Child", 3, List.of(parent.getName()));
        FunctionContainer unchangedChild = function("Parent::Unchanged", false);
        unchangedChild.setImplementationAddress(0x1000);
        child.getVirtualFunctions().put(0, unchangedChild);
        FunctionContainer replacement = function("Child::WrongRecoveredName", false);
        replacement.setImplementationAddress(0x3000);
        child.getVirtualFunctions().put(1, replacement);
        FunctionContainer added = function("Child::Added", false);
        added.setImplementationAddress(0x4000);
        child.getVirtualFunctions().put(2, added);

        FileContainer source = new FileContainer("test");
        source.getClasses().addAll(List.of(parent, child));
        ClassContainer collapsedChild = SDKWriter.collapseContainer(source).getClasses().get(1);

        assertEquals(false, collapsedChild.getVirtualFunctions().containsKey(0));
        assertEquals(true, collapsedChild.getVirtualFunctions().get(1).isOverride());
        assertEquals(
                "Parent::ParentName",
                collapsedChild.getVirtualFunctions().get(1).getName().toString());
        assertEquals(
                "bool",
                collapsedChild.getVirtualFunctions().get(1).getReturnType().getName().toString());
        assertEquals(false, collapsedChild.getVirtualFunctions().get(2).isOverride());
    }

    private static void pureVirtualsGenerateAbstractBasesAndConcreteOverrides() throws IOException {
        ClassContainer parent = cls("AbstractBase", 1, List.of());
        FunctionContainer pure = function("AbstractBase::Run", false);
        pure.setImplementationAddress(0x5000);
        pure.setPureVirtual(true);
        parent.getVirtualFunctions().put(0, pure);

        ClassContainer child = cls("ConcreteChild", 1, List.of(parent.getName()));
        FunctionContainer concrete = function("ConcreteChild::Run", false);
        concrete.setImplementationAddress(0x6000);
        child.getVirtualFunctions().put(0, concrete);

        FileContainer source = new FileContainer("test");
        source.getClasses().addAll(List.of(parent, child));
        Path output = Files.createTempDirectory("symbolweave-pure-virtual-test-");
        try {
            SDKWriter.writeToDirectory(SDKWriter.collapseContainer(source), output);
            assertContains(
                    Files.readString(output.resolve("AbstractBase.h")), "virtual void Run() = 0;");
            assertContains(
                    Files.readString(output.resolve("ConcreteChild.h")),
                    "void Run() override { SDK_VIRTUAL_IMPLEMENTATION(Run_OverrideMetadata, this);"
                            + " }");
        } finally {
            try (var paths = Files.walk(output)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList())
                    Files.deleteIfExists(path);
            }
        }
    }

    private static ClassContainer cls(
            String name, int vtableCount, List<Util.NamespacedString> parents) {
        return new ClassContainer(
                Util.NamespacedString.parse(name),
                0,
                vtableCount,
                new HashMap<>(),
                new ArrayList<>(),
                new ArrayList<>(parents),
                new ArrayList<>());
    }

    private static FunctionContainer function(String name, boolean isOverride) {
        return new FunctionContainer(
                0,
                Util.NamespacedString.parse(name),
                FunctionContainer.CallingConvention.THISCALL,
                TypeContainer.VOID,
                new HashMap<>(),
                isOverride,
                false);
    }

    private static void assertContains(String text, String expected) {
        if (!text.contains(expected))
            throw new AssertionError("Missing generated text: " + expected);
    }

    private static void assertDoesNotContain(String text, String unexpected) {
        if (text.contains(unexpected))
            throw new AssertionError("Unexpected generated text: " + unexpected);
    }

    private static void assertBefore(String text, String first, String second) {
        int firstIndex = text.indexOf(first);
        int secondIndex = text.indexOf(second);
        if (firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex) {
            throw new AssertionError("Expected " + first + " before " + second);
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual))
            throw new AssertionError("Expected " + expected + " but got " + actual);
    }
}
