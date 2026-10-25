package symbolweave;

import symbolweave.containers.*;

import java.nio.file.*;
import java.util.*;

/** Generates a fixture exercised by SDKWriterDirectFunctionTest.cpp. */
public final class SDKWriterDirectFunctionTest {
    public static void main(String[] args) throws Exception {
        Path output =
                args.length == 0
                        ? Files.createTempDirectory("symbolweave-direct-test-")
                        : Path.of(args[0]);
        var owner =
                new ClassContainer(
                        Util.NamespacedString.parse("NativeCallable"),
                        0,
                        0,
                        new HashMap<>(),
                        new ArrayList<>(),
                        new ArrayList<>(),
                        new ArrayList<>());
        owner.getFunctions()
                .add(
                        fn(
                                "NativeCallable",
                                0x10,
                                "NativeCallable",
                                "*",
                                true,
                                parameter("initial", "std::uint32_t")));
        owner.getFunctions().add(fn("NativeCallable", 0x11, "NativeCallable", "*", true));
        owner.getFunctions().add(fn("~NativeCallable", 0x20, "void", "", true));
        owner.getFunctions()
                .add(
                        fn(
                                "Compute",
                                0x30,
                                "std::uint64_t",
                                "",
                                true,
                                parameter("value", "std::uint64_t")));
        owner.getFunctions().add(fn("Ready", 0x40, "bool", "", true));
        owner.getFunctions()
                .add(
                        fn(
                                "GlobalCall",
                                0x50,
                                "std::uint64_t",
                                "",
                                false,
                                parameter("value", "std::uint64_t")));

        var source = new FileContainer("test");
        source.getClasses().add(owner);
        SDKWriter.writeToDirectory(source, output);
        String header = Files.readString(output.resolve("NativeCallable.h"));
        require(
                header,
                "explicit NativeCallable(std::uint32_t initial) { [&]() {"
                    + " SDK_STATIC_IMPLEMENTATION(NativeCallableMetadata, this, initial); }(); }");
        require(
                header,
                "explicit NativeCallable() { [&]() {"
                        + " SDK_STATIC_IMPLEMENTATION(NativeCallable2Metadata, this); }(); }");
        require(
                header,
                "~NativeCallable() { [&]() {"
                    + " SDK_STATIC_IMPLEMENTATION(NativeCallableDeconstructorMetadata, this); }();"
                    + " }");
        require(
                header,
                "std::uint64_t Compute(std::uint64_t value) {"
                        + " SDK_STATIC_IMPLEMENTATION(ComputeMetadata, this, value); }");
        require(header, "bool Ready() { SDK_STATIC_IMPLEMENTATION(ReadyMetadata, this); }");
        require(
                header,
                "std::uint64_t GlobalCall(std::uint64_t value) {"
                        + " SDK_STATIC_IMPLEMENTATION(GlobalCallMetadata, value); }");
        System.out.println("Direct function generation checks passed: " + output);
    }

    private static FunctionContainer fn(
            String name,
            long address,
            String result,
            String suffix,
            boolean receiver,
            ParameterContainer... parameters) {
        var fn = new FunctionContainer(Util.NamespacedString.parse("NativeCallable::" + name));
        fn.setAddress(address);
        fn.setCallingConvention(
                receiver
                        ? FunctionContainer.CallingConvention.THISCALL
                        : FunctionContainer.CallingConvention.CDECL);
        fn.setReturnType(new TypeContainer(Util.NamespacedString.parse(result), "", suffix, false));
        for (int i = 0; i < parameters.length; ++i) fn.getParameters().put(i, parameters[i]);
        return fn;
    }

    private static ParameterContainer parameter(String name, String type) {
        return new ParameterContainer(name, new TypeContainer(Util.NamespacedString.parse(type)));
    }

    private static void require(String header, String expected) {
        if (!header.contains(expected))
            throw new AssertionError("Missing generated definition: " + expected);
    }
}
