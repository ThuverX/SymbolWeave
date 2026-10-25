package symbolweave;

import symbolweave.containers.*;

import java.nio.file.*;
import java.util.*;

public final class SDKWriterCallingConventionTest {
    public static void main(String[] args) throws Exception {
        Path output =
                args.length == 0 ? Files.createTempDirectory("sdk-conventions-") : Path.of(args[0]);
        var source = new FileContainer("test");
        for (var convention : FunctionContainer.CallingConvention.values()) {
            String name = "Abi" + convention.name();
            var owner =
                    new ClassContainer(
                            Util.NamespacedString.parse(name),
                            0,
                            1,
                            new HashMap<>(),
                            new ArrayList<>(),
                            new ArrayList<>(),
                            new ArrayList<>());
            var direct = function(name + "::Direct", convention);
            direct.setStatic(convention != FunctionContainer.CallingConvention.THISCALL);
            owner.getFunctions().add(direct);
            owner.getVirtualFunctions().put(0, function(name + "::Invoke", convention));
            var variadic = function(name + "::Variadic", convention);
            variadic.setVarargs(true);
            owner.getVirtualFunctions().put(1, variadic);
            source.getClasses().add(owner);
            if (convention != FunctionContainer.CallingConvention.THISCALL)
                source.getLooseFunctions().add(function("Loose" + convention.name(), convention));
        }
        var config = new ProjectConfig();
        if (config.outputs.ignoreX86CallingConventions)
            throw new AssertionError("Conventions disabled by default");
        try {
            for (boolean ignore : List.of(false, true)) {
                config.outputs.ignoreX86CallingConventions = ignore;
                SDKWriter.configure(config);
                Path directory = output.resolve(ignore ? "ignored" : "annotated");
                SDKWriter.writeToDirectory(source, directory);
                for (var convention : FunctionContainer.CallingConvention.values()) {
                    String name = "Abi" + convention.name();
                    String header = Files.readString(directory.resolve(name + ".h"));
                    String cc = ignore ? "" : "SDK_" + convention.name() + " ";
                    require(header, "int (" + cc + "*)(" + name + "*, int)");
                    require(header, "int " + cc + "Invoke(int value)");
                    require(header, "int " + cc + "Direct(int value)");
                    require(
                            header,
                            "int ("
                                    + cc
                                    + "*)("
                                    + (convention == FunctionContainer.CallingConvention.THISCALL
                                            ? name + "*, "
                                            : "")
                                    + "int)");
                    String variadicCC = ignore ? "" : "SDK_CDECL ";
                    require(header, "int (" + variadicCC + "*)(" + name + "*, int, ...)");
                    require(header, "int " + variadicCC + "Variadic(int value, ...)");
                    if (ignore && header.contains("SDK_THISCALL")) throw new AssertionError(header);
                    if (convention != FunctionContainer.CallingConvention.THISCALL) {
                        String global = Files.readString(directory.resolve("Global.h"));
                        require(global, "int " + cc + "Loose" + convention.name() + "(int value)");
                        require(global, "int (" + cc + "*)(int)");
                    }
                }
            }
        } finally {
            SDKWriter.configure(new ProjectConfig());
        }
        System.out.println("Calling convention generation passed: " + output);
    }

    private static FunctionContainer function(
            String name, FunctionContainer.CallingConvention convention) {
        var function = new FunctionContainer(Util.NamespacedString.parse(name));
        function.setCallingConvention(convention);
        function.setReturnType(new TypeContainer(Util.NamespacedString.parse("int")));
        function.getParameters()
                .put(
                        0,
                        new ParameterContainer(
                                "value", new TypeContainer(Util.NamespacedString.parse("int"))));
        return function;
    }

    private static void require(String header, String expected) {
        if (!header.contains(expected))
            throw new AssertionError("Missing: " + expected + "\n" + header);
    }
}
