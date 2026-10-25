package symbolweave;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;

import symbolweave.containers.*;

import java.lang.reflect.Proxy;
import java.util.*;

/** Exercises export independently of any game's symbols or RTTI. */
public final class PcFunctionLoaderTest {
    public static void main(String[] args) {
        ghidra.util.UniversalIdGenerator.initialize();
        Namespace global = stub(Namespace.class, Map.of("getName", ""));
        GhidraClass owner = stub(GhidraClass.class, Map.of("getName", "Example::Worker"));
        Parameter receiver = parameter("this", new PointerDataType(VoidDataType.dataType, 8), true);
        Parameter count = parameter("count", UnsignedIntegerDataType.dataType, false);
        Function loose = function("Log", global, 0x140001000L, "__cdecl", true, false, count);
        Function member =
                function(
                        "Example::Worker::Run",
                        owner,
                        0x140002000L,
                        "__fastcall",
                        false,
                        false,
                        receiver,
                        count);
        Function external = function("External", global, 0, "__cdecl", false, true);
        Iterator<Function> iterator = List.of(loose, member, external).iterator();
        FunctionIterator functions =
                (FunctionIterator)
                        Proxy.newProxyInstance(
                                PcFunctionLoaderTest.class.getClassLoader(),
                                new Class<?>[] {FunctionIterator.class},
                                (proxy, method, arguments) ->
                                        switch (method.getName()) {
                                            case "iterator" -> proxy;
                                            case "hasNext" -> iterator.hasNext();
                                            case "next" -> iterator.next();
                                            default -> throw new AssertionError(method.getName());
                                        });
        FunctionManager manager = stub(FunctionManager.class, Map.of("getFunctions", functions));
        Program program =
                stub(
                        Program.class,
                        Map.of("getName", "fixture.exe", "getFunctionManager", manager));
        FileContainer result = new PcFunctionLoader().loadFromFunctions(program);
        equal(1, result.getLooseFunctions().size());
        FunctionContainer exported = result.getLooseFunctions().getFirst();
        equal(0x140001000L, exported.getAddress());
        equal(true, exported.isVarargs());
        equal("std::uint32_t", exported.getParameters().get(0).getType().getName().toString());
        equal("std::int32_t", exported.getReturnType().getName().toString());
        equal(1, result.getClasses().size());
        ClassContainer cls = result.getClasses().getFirst();
        equal(0, cls.getVirtualFunctions().size());
        equal(0, cls.getParents().size());
        equal(1, cls.getFunctions().getFirst().getParameters().size());
        equal(
                FunctionContainer.CallingConvention.THISCALL,
                cls.getFunctions().getFirst().getCallingConvention());
        equal(false, cls.getFunctions().getFirst().isStatic());
        equal(
                "undefined8",
                PcFunctionLoader.toType(Undefined8DataType.dataType).getName().toString());
        TypeContainer pointer =
                PcFunctionLoader.toType(new PointerDataType(UnsignedIntegerDataType.dataType, 8));
        equal("std::uint32_t", pointer.getName().toString());
        equal("*", pointer.getSuffix());
        FileContainer merged = ConfigurableMerger.merge(List.of(result));
        equal(1, merged.getLooseFunctions().size());
    }

    private static Function function(
            String name,
            Namespace owner,
            long address,
            String convention,
            boolean varargs,
            boolean external,
            Parameter... parameters) {
        Address entry = stub(Address.class, Map.of("getOffset", address));
        return stub(
                Function.class,
                Map.of(
                        "getName",
                        name,
                        "getParentNamespace",
                        owner,
                        "getCallingConventionName",
                        convention,
                        "getEntryPoint",
                        entry,
                        "getReturnType",
                        IntegerDataType.dataType,
                        "getParameters",
                        parameters,
                        "hasVarArgs",
                        varargs,
                        "isExternal",
                        external));
    }

    private static Parameter parameter(String name, DataType type, boolean auto) {
        return stub(
                Parameter.class,
                Map.of("getName", name, "getDataType", type, "isAutoParameter", auto));
    }

    private static <T> T stub(Class<T> type, Map<String, Object> values) {
        return type.cast(
                Proxy.newProxyInstance(
                        PcFunctionLoaderTest.class.getClassLoader(),
                        new Class<?>[] {type},
                        (proxy, method, arguments) -> {
                            if (values.containsKey(method.getName()))
                                return values.get(method.getName());
                            throw new AssertionError(
                                    "Unexpected access: "
                                            + type.getSimpleName()
                                            + "."
                                            + method.getName());
                        }));
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
    }
}
