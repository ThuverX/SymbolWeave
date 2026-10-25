package symbolweave;

import com.google.gson.*;

import symbolweave.containers.*;

import java.nio.file.*;
import java.util.*;

public final class ConfigurablePipelineTest {
    public static void main(String[] args) throws Exception {
        mergePolicies();
        omissionAndClear();
        stripAddresses();
        stripAddressesPipeline();
        matching();
        endToEndXml();
        System.out.println(
                "Configurable merge, matching, XML-only pipeline, and checker substitutions"
                        + " passed");
    }

    static FileContainer file(FunctionContainer f) {
        var file = new FileContainer("test");
        var cls = new ClassContainer(Util.NamespacedString.parse("C"));
        cls.getVirtualFunctions().put(0, f);
        file.getClasses().add(cls);
        return file;
    }

    static FunctionContainer fn(String name, long address) {
        return new FunctionContainer(
                address,
                Util.NamespacedString.parse(name),
                FunctionContainer.CallingConvention.THISCALL,
                TypeContainer.VOID,
                new HashMap<>(),
                false,
                false);
    }

    static FunctionContainer merged(FileContainer a, FileContainer b, ProjectConfig.Merge policy) {
        return ConfigurableMerger.merge(
                        List.of(
                                new ConfigurableMerger.Layer(a, false),
                                new ConfigurableMerger.Layer(b, true)),
                        policy)
                .getClasses()
                .getFirst()
                .getVirtualFunctions()
                .get(0);
    }

    static void mergePolicies() {
        var a = file(fn("C::Old", 11));
        var b = file(fn("C::New", 22));
        var policy = new ProjectConfig.Merge();
        policy.fields.put("function.address", "keep");
        var result = merged(a, b, policy);
        ProjectConfigTest.equal(11L, result.getAddress());
        ProjectConfigTest.equal("C::New", result.getName().toString());
        ProjectConfigTest.equal(
                "C::Old",
                a.getClasses().getFirst().getVirtualFunctions().get(0).getName().toString());
        var override = new ProjectConfig.Policy();
        override.fields.put("function.address", "replace");
        var perLayer =
                ConfigurableMerger.merge(
                        List.of(
                                new ConfigurableMerger.Layer(a, false),
                                new ConfigurableMerger.Layer(b, true, override)),
                        policy);
        ProjectConfigTest.equal(
                22L, perLayer.getClasses().getFirst().getVirtualFunctions().get(0).getAddress());
        policy.fields.put("function.name", "error");
        try {
            merged(a, b, policy);
            throw new AssertionError("Conflict accepted");
        } catch (IllegalArgumentException expected) {
        }
        policy.fields.put("function.name", "keep");
        policy.fields.put("class.virtualFunctions", "keep");
        ProjectConfigTest.equal("C::Old", merged(a, b, policy).getName().toString());
        policy.fields.put("class.virtualFunctions", "replace");
        policy.fields.put("function.name", "replace");
        ProjectConfigTest.equal(22L, merged(a, b, policy).getAddress());
    }

    static void stripAddresses() throws Exception {
        var reference =
                xml(
                        """
                        <Data><Functions><Function name="Loose" address="0x110" implementationAddress="0x111"/></Functions>
                        <Classes><Class name="C" address="0x100" vtableCount="2"><Functions>
                        <VirtualFunction index="0" name="C::Run" address="0x120" implementationAddress="0x121" clear="address,implementationAddress"/>
                        <VirtualFunction index="1" name="C::New" address="0x130" implementationAddress="0x131"/>
                        <Function name="C::Regular" address="0x140" implementationAddress="0x141"/>
                        </Functions><Members><Member name="data" address="0x150" offset="4" size="4"/></Members>
                        </Class><Class name="NewClass" address="0x160"><Functions>
                        <VirtualFunction index="0" name="NewClass::Run" address="0x170" implementationAddress="0x171"/>
                        </Functions></Class></Classes></Data>
                        """);
        var strip = new ProjectConfig.Policy();
        strip.stripAddresses = true;
        for (boolean respectOmitted : List.of(true, false)) {
            var settings = new ProjectConfig.Merge();
            settings.respectOmitted = respectOmitted;
            settings.functionKey = "name";
            settings.fields.put("function.address", "replace");
            settings.fields.put("function.implementationAddress", "replace");
            settings.fields.put("class.vtableAddress", "replace");
            settings.fields.put("member.address", "replace");
            var pc =
                    xml(
                            """
                            <Data><Functions><Function name="Loose" address="0x210" implementationAddress="0x211"/></Functions>
                            <Classes><Class name="C" address="0x200"><Functions>
                            <VirtualFunction index="0" name="C::Old" address="0x220" implementationAddress="0x221"/>
                            <Function name="C::Regular" address="0x240" implementationAddress="0x241"/>
                            </Functions><Members><Member name="data" address="0x250"/></Members>
                            </Class></Classes></Data>
                            """);
            var merged =
                    ConfigurableMerger.merge(
                            List.of(
                                    new ConfigurableMerger.Layer(pc, false),
                                    new ConfigurableMerger.Layer(reference, false, strip)),
                            settings);
            var cls = merged.getClasses().getFirst();
            ProjectConfigTest.equal(0x200L, cls.getVtableAddress());
            ProjectConfigTest.equal(
                    "C::Run", cls.getVirtualFunctions().get(0).getName().toString());
            ProjectConfigTest.equal(0x220L, cls.getVirtualFunctions().get(0).getAddress());
            ProjectConfigTest.equal(
                    0x221L, cls.getVirtualFunctions().get(0).getImplementationAddress());
            ProjectConfigTest.equal(0L, cls.getVirtualFunctions().get(1).getAddress());
            ProjectConfigTest.equal(
                    0L, cls.getVirtualFunctions().get(1).getImplementationAddress());
            ProjectConfigTest.equal(0x240L, cls.getFunctions().getFirst().getAddress());
            ProjectConfigTest.equal(
                    0x241L, cls.getFunctions().getFirst().getImplementationAddress());
            ProjectConfigTest.equal(0x250L, cls.getMembers().getFirst().getAddress());
            ProjectConfigTest.equal(4L, cls.getMembers().getFirst().getOffset());
            ProjectConfigTest.equal(0x210L, merged.getLooseFunctions().getFirst().getAddress());
            ProjectConfigTest.equal(
                    0x211L, merged.getLooseFunctions().getFirst().getImplementationAddress());
            ProjectConfigTest.equal(0L, merged.getClasses().get(1).getVtableAddress());
            ProjectConfigTest.equal(
                    0L, merged.getClasses().get(1).getVirtualFunctions().get(0).getAddress());
        }
        var settings = new ProjectConfig.Merge();
        settings.stripAddresses = true;
        var stripped =
                ConfigurableMerger.merge(
                        List.of(new ConfigurableMerger.Layer(reference, false)), settings);
        ProjectConfigTest.equal(0L, stripped.getLooseFunctions().getFirst().getAddress());
        ProjectConfigTest.equal(
                0L, stripped.getLooseFunctions().getFirst().getImplementationAddress());
        ProjectConfigTest.equal(
                0L, stripped.getClasses().getFirst().getFunctions().getFirst().getAddress());
        ProjectConfigTest.equal(
                null, stripped.getClasses().getFirst().getMembers().getFirst().getAddress());
        ProjectConfigTest.equal(0x100L, reference.getClasses().getFirst().getVtableAddress());
        ProjectConfigTest.equal(
                0x120L,
                reference.getClasses().getFirst().getVirtualFunctions().get(0).getAddress());
        ProjectConfigTest.equal(0x110L, reference.getLooseFunctions().getFirst().getAddress());
        ProjectConfigTest.equal(
                0x150L, reference.getClasses().getFirst().getMembers().getFirst().getAddress());
        var allow = new ProjectConfig.Policy();
        allow.stripAddresses = false;
        var restored =
                ConfigurableMerger.merge(
                        List.of(
                                new ConfigurableMerger.Layer(reference, false),
                                new ConfigurableMerger.Layer(reference, true, allow)),
                        settings);
        ProjectConfigTest.equal(0x100L, restored.getClasses().getFirst().getVtableAddress());
        ProjectConfigTest.equal(
                0x130L, restored.getClasses().getFirst().getVirtualFunctions().get(1).getAddress());
        // The default remains unchanged, even after merging the same input with stripping enabled.
        var original =
                ConfigurableMerger.merge(
                        List.of(new ConfigurableMerger.Layer(reference, false)),
                        new ProjectConfig.Merge());
        ProjectConfigTest.equal(
                0x130L, original.getClasses().getFirst().getVirtualFunctions().get(1).getAddress());
    }

    static void stripAddressesPipeline() throws Exception {
        Path root = Files.createTempDirectory("sdk-strip-addresses-");
        Files.writeString(
                root.resolve("reference.xml"),
                """
                <Data><Classes><Class name="C" address="0x100" vtableCount="2"><Functions>
                <VirtualFunction index="0" name="C::Run" address="0x110" implementationAddress="0x111"/>
                <VirtualFunction index="1" name="C::Other" address="0x120" implementationAddress="0x121"/>
                </Functions></Class></Classes></Data>
                """);
        Files.writeString(
                root.resolve("pc.xml"),
                """
                <Data><Classes><Class name="C" address="0x200"><Functions>
                <VirtualFunction index="0" address="0x210" implementationAddress="0x211"/>
                </Functions></Class></Classes></Data>
                """);
        Files.writeString(
                root.resolve("patch.xml"),
                """
                <Data><Classes><Class name="C" address="0x300"><Functions>
                <VirtualFunction index="1" address="0x310" implementationAddress="0x311"/>
                </Functions></Class></Classes></Data>
                """);
        Files.writeString(
                root.resolve("config.json"),
                """
                {"version":1,"analyze":false,"inputs":[
                  {"id":"ps2","xml":"reference.xml"},{"id":"pc","xml":"pc.xml"}],
                 "merge":{"sources":["ps2","pc"],"sourcePolicies":{"ps2":{"stripAddresses":true}},
                  "patches":[{"files":["patch.xml"],"order":"listed","headerFromFilename":false}]},
                 "outputs":{"xml":"merged.xml","headers":"headers"}}
                """);
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        var cls =
                DataXMLSerializer.readContainerFromFile(root.resolve("merged.xml"))
                        .getClasses()
                        .getFirst();
        ProjectConfigTest.equal(0x300L, cls.getVtableAddress());
        ProjectConfigTest.equal(2, cls.getVirtualFunctions().size());
        ProjectConfigTest.equal("C::Run", cls.getVirtualFunctions().get(0).getName().toString());
        ProjectConfigTest.equal(0x210L, cls.getVirtualFunctions().get(0).getAddress());
        ProjectConfigTest.equal(
                0x211L, cls.getVirtualFunctions().get(0).getImplementationAddress());
        ProjectConfigTest.equal("C::Other", cls.getVirtualFunctions().get(1).getName().toString());
        ProjectConfigTest.equal(0x310L, cls.getVirtualFunctions().get(1).getAddress());
        ProjectConfigTest.equal(
                0x311L, cls.getVirtualFunctions().get(1).getImplementationAddress());
    }

    static FileContainer xml(String body) throws Exception {
        var builder = new org.jdom2.input.SAXBuilder();
        return DataXMLSerializer.deserialize(
                builder.build(new java.io.StringReader(body)).getRootElement());
    }

    static void omissionAndClear() throws Exception {
        var base = fn("C::Run", 100);
        base.setReturnType(new TypeContainer(Util.NamespacedString.parse("bool")));
        base.setStatic(true);
        base.getParameters().put(0, new ParameterContainer("p", TypeContainer.VOIDPTR));
        var omitted =
                xml(
                        "<Data><Classes><Class name='C'><Functions><VirtualFunction index='0'"
                                + " name='C::Renamed'/></Functions></Class></Classes></Data>");
        var result = merged(file(base), omitted, new ProjectConfig.Merge());
        ProjectConfigTest.equal("bool", result.getReturnType().getName().toString());
        ProjectConfigTest.equal(true, result.isStatic());
        ProjectConfigTest.equal(1, result.getParameters().size());
        var clear =
                xml(
                        "<Data><Classes><Class name='C'><Functions><VirtualFunction index='0'"
                                + " name='C::Run' isStatic='false'"
                                + " clear='parameters'/></Functions></Class></Classes></Data>");
        result = merged(file(base), clear, new ProjectConfig.Merge());
        ProjectConfigTest.equal(false, result.isStatic());
        ProjectConfigTest.equal(0, result.getParameters().size());
    }

    static void matching() throws Exception {
        var source = file(fn("C::Run", 1));
        var target = file(fn("C::Run", 99));
        var rule = new ProjectConfig.Match();
        rule.source = "s";
        rule.target = "t";
        rule.plugin = "function-match";
        rule.options =
                JsonParser.parseString(
                                "{\"fields\":{\"returnType\":\"bool\",\"address\":\"$target.address\"}}")
                        .getAsJsonObject();
        var plugin =
                BuiltinPlugins.all().stream()
                        .filter(p -> p.name().equals(rule.plugin))
                        .findFirst()
                        .orElseThrow();
        plugin.validate(rule.options);
        plugin.match(null, rule, Map.of("s", source, "t", target));
        var result = target.getClasses().getFirst().getVirtualFunctions().get(0);
        ProjectConfigTest.equal(99L, result.getAddress());
        ProjectConfigTest.equal("bool", result.getReturnType().getName().toString());
        source.getClasses().getFirst().getFunctions().add(fn("C::Run", 2));
        try {
            plugin.match(null, rule, Map.of("s", source, "t", target));
            throw new AssertionError("Ambiguity accepted");
        } catch (IllegalArgumentException expected) {
        }
        source.getClasses()
                .getFirst()
                .getVirtualFunctions()
                .get(0)
                .setReturnType(new TypeContainer(Util.NamespacedString.parse("bool")));
        rule.options =
                JsonParser.parseString(
                                "{\"sourceKey\":\"returnType\",\"targetKey\":\"returnType\",\"fields\":{\"name\":\"C::Typed\"}}")
                        .getAsJsonObject();
        plugin.match(null, rule, Map.of("s", source, "t", target));
        ProjectConfigTest.equal(
                "C::Typed",
                target.getClasses().getFirst().getVirtualFunctions().get(0).getName().toString());
        Map<Integer, FunctionContainer> slots = new HashMap<>();
        slots.put(0, fn("C::A", 1));
        slots.put(1, null);
        slots.put(2, null);
        slots.put(3, fn("C::B", 2));
        ProjectConfigTest.equal(2, BuiltinPlugins.remap(slots, 1, 2).size());
    }

    static void endToEndXml() throws Exception {
        Path root = Files.createTempDirectory("sdk-pipeline-");
        Files.writeString(
                root.resolve("data.xml"),
                "<Data><Functions><Function name='Run' address='0x1000'"
                        + " callingConvention='__cdecl'><ReturnType"
                        + " type='void'/></Function></Functions></Data>");
        Files.writeString(
                root.resolve("config.json"),
                "{\"version\":1,\"analyze\":false,\"inputs\":[{\"id\":\"xml\",\"xml\":\"data.xml\"}],\"outputs\":{\"supportHeaders\":[],\"xml\":\"output/result.xml\",\"headers\":\"headers\"}}");
        Main.main(new String[] {"-c", root.resolve("config.json").toString()});
        if (!Files.isRegularFile(root.resolve("headers/Global.h"))
                || !Files.isRegularFile(root.resolve("output/result.xml")))
            throw new AssertionError("Output missing");
        String runtime = Files.readString(root.resolve("headers/SdkMetadata.h"));
        if (!runtime.contains("SDK_STATIC_IMPLEMENTATION")
                || !runtime.contains("SDK_REBASE_ADDRESS"))
            throw new AssertionError("Bundled runtime header is incomplete");
        ProjectConfig config = ProjectConfig.load(root.resolve("config.json"));
        config.checker.opaqueNamespaces.add("library::");
        config.checker.removeIncludeRegex.add("(?m)^#include.*library.*\\R?");
        VtableChecker.configure(config);
        String result =
                VtableChecker.prepareHeader(
                        "#include <library/vector.h>\n"
                                + "library::vector<library::pair<int, int>>* v;");
        if (result.contains("library::") || !result.contains("Opaque<"))
            throw new AssertionError(result);
    }
}
