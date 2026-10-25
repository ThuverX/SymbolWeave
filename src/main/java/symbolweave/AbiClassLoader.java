package symbolweave;

import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;

import mdemangler.MDMang;
import mdemangler.MDParsableItem;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.ParameterContainer;
import symbolweave.containers.TypeContainer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Spliterators;
import java.util.stream.StreamSupport;

/** Platform ABI recovery selected and parameterized by extractor options. */
public class AbiClassLoader {
    private final com.google.gson.JsonObject options;

    public AbiClassLoader(com.google.gson.JsonObject options) {
        this.options = options;
    }

    private int integer(String key, int fallback) {
        return Options.integer(options, key, fallback);
    }

    private String text(String key, String fallback) {
        return Options.string(options, key, fallback);
    }

    private boolean enabled(String key) {
        return Options.bool(options, key, true);
    }

    public FileContainer loadFromMap(List<SymbolMapLoader.Entry> entries, GhidraWorkspace workspace)
            throws MemoryAccessException {
        Program program = workspace.getProgram();
        var vtablePattern =
                java.util.regex.Pattern.compile(Options.required(options, "vtableRegex"));
        List<SymbolMapLoader.Entry> vtableEntries =
                entries.stream().filter(e -> vtablePattern.matcher(e.name).find()).toList();

        FileContainer fc = new FileContainer(workspace.getProgram().getName());

        Set<SymbolMapLoader.Entry> usedFunctions = new java.util.HashSet<>();
        Map<Long, SymbolMapLoader.Entry> functionsByAddress = new HashMap<>();
        for (var entry : entries)
            if (entry.function()) functionsByAddress.putIfAbsent(entry.address, entry);

        for (SymbolMapLoader.Entry vtableEntry : vtableEntries) {
            DemangledObject demangledName = vtableEntry.demangled();
            if (demangledName == null || demangledName.getNamespace() == null)
                throw new IllegalArgumentException(
                        "Vtable symbol could not be demangled: " + vtableEntry.name);
            Util.NamespacedString namespacedName =
                    Util.NamespacedString.parse(demangledName.getNamespace().getNamespaceString());
            long vtableAddress = vtableEntry.address;

            int vtableCount =
                    (int)
                                    (vtableEntry.size
                                            / integer(
                                                    "pointerSize", program.getDefaultPointerSize()))
                            - integer("headerSlots", 0);

            HashMap<Integer, FunctionContainer> functions = new HashMap<>();
            List<Util.NamespacedString> parents = new ArrayList<>();

            for (int i = 0; i < vtableCount; i++) {
                functions.put(i, null);
                long ptrAddress =
                        vtableAddress
                                + ((long) (i + integer("headerSlots", 0))
                                        * integer("pointerSize", program.getDefaultPointerSize()));

                Address address =
                        program.getAddressFactory().getDefaultAddressSpace().getAddress(ptrAddress);

                long funAddress =
                        readPointer(
                                program,
                                address,
                                integer("pointerSize", program.getDefaultPointerSize()));

                SymbolMapLoader.Entry functionEntry = functionsByAddress.get(funAddress);

                if (functionEntry != null) {

                    usedFunctions.add(functionEntry);

                    try {
                        FunctionContainer functionContainer =
                                parseFunction(
                                        functionEntry,
                                        FunctionContainer.CallingConvention.valueOf(
                                                text("virtualCallingConvention", "THISCALL")));
                        functionContainer.setImplementationAddress(functionEntry.address);
                        if (!functionContainer.getName().isTopLevel()) {
                            Util.NamespacedString fnNs = functionContainer.getName().parent();

                            if (!fnNs.equals(namespacedName)) {
                                if (!parents.contains(fnNs)) {
                                    parents.add(fnNs);
                                }
                            }
                        }

                        functions.put(i, functionContainer);
                    } catch (Exception e) {
                        System.out.println(
                                "Failed for " + functionEntry.name + ": " + e.getMessage());
                    }
                }
            }

            fc.getClasses()
                    .add(
                            new ClassContainer(
                                    namespacedName,
                                    vtableAddress,
                                    vtableCount,
                                    functions,
                                    new ArrayList<>(),
                                    parents,
                                    new ArrayList<>()));
        }

        // Non-virtual class declarations.
        if (enabled("includeClassFunctions")) {
            List<SymbolMapLoader.Entry> regularFunctions =
                    entries.stream()
                            .filter((entry) -> entry.function() && !usedFunctions.contains(entry))
                            .toList();

            for (SymbolMapLoader.Entry regularFunction : regularFunctions) {
                DemangledObject demangledName = regularFunction.demangled();

                if (demangledName == null) continue;
                if (demangledName.getNamespace() == null) continue;

                Util.NamespacedString parentNamespace =
                        Util.NamespacedString.parse(
                                demangledName.getNamespace().getNamespaceString());

                ClassContainer cc =
                        fc.getClasses().stream()
                                .filter(c -> c.getName().equals(parentNamespace))
                                .findFirst()
                                .orElse(null);

                if (cc != null) {
                    try {
                        FunctionContainer functionContainer =
                                parseFunction(
                                        regularFunction,
                                        FunctionContainer.CallingConvention.valueOf(
                                                text("functionCallingConvention", "STDCALL")));

                        cc.getFunctions().add(functionContainer);
                        usedFunctions.add(regularFunction);
                    } catch (Exception e) {
                        System.out.println(
                                "Failed for " + regularFunction.name + ": " + e.getMessage());
                    }
                }
            }
        }

        if (enabled("includeLooseFunctions")) {
            List<SymbolMapLoader.Entry> looseFunctions =
                    entries.stream()
                            .filter((entry) -> entry.function() && !usedFunctions.contains(entry))
                            .toList();

            for (SymbolMapLoader.Entry looseFunction : looseFunctions) {
                DemangledObject demangledName = looseFunction.demangled();

                if (demangledName == null) continue;

                try {
                    FunctionContainer functionContainer =
                            parseFunction(
                                    looseFunction,
                                    FunctionContainer.CallingConvention.valueOf(
                                            text("functionCallingConvention", "STDCALL")));

                    fc.getLooseFunctions().add(functionContainer);
                } catch (Exception e) {
                    System.out.println("Failed for " + looseFunction.name + ": " + e.getMessage());
                }
            }
        }

        return fc;
    }

    public FunctionContainer parseFunction(
            SymbolMapLoader.Entry entry, FunctionContainer.CallingConvention cv) {
        DemangledFunction demangledObject = (DemangledFunction) entry.demangled();

        String nsName = demangledObject.getName();

        if (demangledObject.getNamespace() != null) {
            nsName = demangledObject.getNamespace().getNamespaceString() + "::" + nsName;
        }

        Util.NamespacedString namespacedName = Util.NamespacedString.parse(nsName);
        Util.NamespacedString returnType =
                Util.NamespacedString.parse("undefined" + entry.storageSize);

        Map<Integer, ParameterContainer> parameters = new HashMap<>();
        int idx = 0;

        for (var param : demangledObject.getParameters()) {
            DemangledDataType dataType = param.getType();

            String dtName = dataType.getName();

            if (dataType.getNamespace() != null) {
                dtName = dataType.getNamespace().getNamespaceString() + "::" + dtName;
            }

            Util.NamespacedString paramType = Util.NamespacedString.parse(dtName);

            String name = param.getLabel();
            if (name == null || name.isEmpty()) {

                if (dataType.getPointerLevels() > 0) {
                    name = "pParam" + idx;
                } else {
                    name = "param" + idx;
                }
            }

            String prefix = "";
            String suffix = "*".repeat(dataType.getPointerLevels());

            if (dataType.isRValueReference()) {
                suffix += "&&";
            } else if (dataType.isLValueReference()) {
                suffix += "&";
            }

            parameters.put(
                    idx,
                    new ParameterContainer(
                            name,
                            new TypeContainer(paramType, prefix, suffix, dataType.isConst())));
            idx++;
        }

        return new FunctionContainer(
                entry.address,
                namespacedName,
                cv,
                new TypeContainer(returnType),
                parameters,
                false,
                false);
    }

    static String readCString(Program program, long pointer) throws MemoryAccessException {
        Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(pointer);

        StringBuilder result = new StringBuilder();

        while (true) {
            byte b = program.getMemory().getByte(address);

            if (b == 0) break;

            result.append((char) (b & 0xFF));
            address = address.add(1);
        }

        return result.toString();
    }

    public FileContainer loadFromRTTI(GhidraWorkspace workspace) throws Exception {
        Program program = workspace.getProgram();

        FileContainer fc = new FileContainer(workspace.getProgram().getName());

        List<Symbol> symbols =
                StreamSupport.stream(
                                Spliterators.spliteratorUnknownSize(
                                        program.getSymbolTable().getAllSymbols(true), 0),
                                false)
                        .toList();

        var purePattern = java.util.regex.Pattern.compile(text("pureVirtualRegex", "(?i)purecall"));
        var vtablePattern = java.util.regex.Pattern.compile(text("vtableSymbolRegex", "vftable"));
        var basePattern =
                java.util.regex.Pattern.compile(
                        text("baseArraySymbolRegex", "RTTI_Base_Class_Array"));
        Set<Long> pureVirtualAddresses = new java.util.HashSet<>();
        Map<String, Symbol> baseArrays = new HashMap<>();
        List<Symbol> vtableSymbols = new ArrayList<>();
        for (Symbol symbol : symbols) {
            if (purePattern.matcher(symbol.getName()).find())
                pureVirtualAddresses.add(symbol.getAddress().getOffset());
            if (vtablePattern.matcher(symbol.getName()).matches()) vtableSymbols.add(symbol);
            if (basePattern.matcher(symbol.getName()).matches())
                baseArrays.putIfAbsent(symbol.getParentNamespace().getName(true), symbol);
        }
        vtableSymbols.sort(Comparator.comparingLong(symbol -> symbol.getAddress().getOffset()));
        if (Options.bool(options, "followPureVirtualThunks", true)) {
            for (var function : program.getFunctionManager().getFunctions(true))
                if (function.isThunk()) {
                    var target = function.getThunkedFunction(true);
                    if (target != null && purePattern.matcher(target.getName()).find())
                        pureVirtualAddresses.add(function.getEntryPoint().getOffset());
                }
        }

        for (Symbol vtableSymbol : vtableSymbols) {
            Util.NamespacedString ns =
                    Util.NamespacedString.parse(vtableSymbol.getParentNamespace().getName(true));

            HashMap<Integer, FunctionContainer> functions = new HashMap<>();

            DataType dt = getDataTypeAt(program, vtableSymbol.getAddress());

            int vtableCount = dt != null ? dt.getLength() / program.getDefaultPointerSize() : 0;

            for (int i = 0; i < vtableCount; i++) {
                Address slotAddress =
                        vtableSymbol.getAddress().add((long) i * program.getDefaultPointerSize());
                long implementationAddress =
                        readPointer(program, slotAddress, program.getDefaultPointerSize());
                FunctionContainer function =
                        new FunctionContainer(
                                slotAddress.getOffset(),
                                Util.NamespacedString.parse("undefined"),
                                FunctionContainer.CallingConvention.THISCALL,
                                TypeContainer.VOID,
                                new HashMap<>(),
                                false,
                                false);
                function.setImplementationAddress(implementationAddress);
                if (pureVirtualAddresses.contains(implementationAddress))
                    function.setPureVirtual(true);
                functions.put(i, function);
            }

            List<Util.NamespacedString> parents = new ArrayList<>();

            Symbol baseClassSymbol = baseArrays.get(ns.toString());

            if (baseClassSymbol != null) {
                DataType baseClassArrayDt = getDataTypeAt(program, baseClassSymbol.getAddress());

                int rttiPointerSize = integer("rttiPointerSize", 4);
                int count = baseClassArrayDt.getLength() / rttiPointerSize;

                for (int i = integer("baseArraySkip", 1); i < count; i++) {
                    Address slotAddress =
                            baseClassSymbol.getAddress().add((long) i * rttiPointerSize);

                    Address baseClassDescriptorAddress = readRttiPointer(program, slotAddress);

                    if (baseClassDescriptorAddress == null) {
                        continue;
                    }

                    Address typeDescriptorAddress =
                            readRttiPointer(program, baseClassDescriptorAddress);

                    if (typeDescriptorAddress == null) {
                        continue;
                    }

                    String name =
                            readCString(
                                    program,
                                    typeDescriptorAddress
                                            .add(integer("typeNameOffset", 16))
                                            .getOffset());

                    MDMang demangler = new MDMang();
                    demangler.setMangledSymbol(name);
                    MDParsableItem item = demangler.demangle();

                    String demangled =
                            item.toString()
                                    .replaceFirst(
                                            text("typeNameStripRegex", "^(class |struct )"), "");

                    Util.NamespacedString namespacedName = Util.NamespacedString.parse(demangled);

                    parents.add(namespacedName);
                }
            }

            ClassContainer existingClass =
                    fc.getClasses().stream()
                            .filter(c -> c.getName().equals(ns))
                            .findFirst()
                            .orElse(null);
            if (existingClass != null) {
                int slotOffset =
                        Math.max(
                                existingClass.getVtableCount(),
                                existingClass.getVirtualFunctions().keySet().stream()
                                        .mapToInt(index -> index + 1)
                                        .max()
                                        .orElse(0));
                for (Map.Entry<Integer, FunctionContainer> function : functions.entrySet()) {
                    existingClass
                            .getVirtualFunctions()
                            .put(slotOffset + function.getKey(), function.getValue());
                }
                for (Util.NamespacedString parent : parents) {
                    if (!existingClass.getParents().contains(parent)) {
                        existingClass.getParents().add(parent);
                    }
                }
                continue;
            }
            fc.getClasses()
                    .add(
                            new ClassContainer(
                                    ns,
                                    vtableSymbol.getAddress().getOffset(),
                                    vtableCount,
                                    functions,
                                    new ArrayList<>(),
                                    parents,
                                    new ArrayList<>()));
        }

        return fc;
    }

    public Address readRttiPointer(Program program, Address address) throws MemoryAccessException {

        long rva = readPointer(program, address, integer("rttiPointerSize", 4));

        if (rva == 0) {
            return null;
        }

        return Options.bool(options, "rttiRelative", true)
                ? program.getImageBase().add(rva)
                : program.getAddressFactory().getDefaultAddressSpace().getAddress(rva);
    }

    private static long readPointer(Program program, Address address, int width)
            throws MemoryAccessException {
        return switch (width) {
            case 4 -> Integer.toUnsignedLong(program.getMemory().getInt(address));
            case 8 -> program.getMemory().getLong(address);
            default ->
                    throw new IllegalArgumentException(
                            "Pointer width must be 4 or 8, got " + width);
        };
    }

    static DataType getDataTypeAt(Program program, Address address) {
        Data data = program.getListing().getDataContaining(address);
        return data != null ? data.getDataType() : null;
    }
}
