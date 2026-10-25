package symbolweave;

import com.google.gson.*;

import symbolweave.containers.*;

import java.nio.file.*;
import java.util.*;

public final class ConfigurablePipelineTest {
    public static void main(String[] args) throws Exception {
        mergePolicies();
        omissionAndClear();
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
