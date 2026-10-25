// Imports symbols and function signatures from the full merged data in sdk.xml.
// @category SymbolWeave

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

public class ImportSdkXml extends GhidraScript {

    private String DATA_TYPE_ROOT = "/SymbolWeave";
    private static final File DEFAULT_XML_FILE = new File("build/metadata/merged.xml");

    private final Map<String, Namespace> namespaces = new HashMap<>();
    private final Map<String, DataType> classTypes = new HashMap<>();
    private final List<String> failures = new ArrayList<>();

    private SymbolTable symbolTable;
    private DataTypeManager dataTypeManager;
    private Memory memory;
    private AddressSpace addressSpace;
    private int pointerSize;

    private int classCount;
    private int vtableCount;
    private int vtableLabelsCreated;
    private int functionCount;
    private int functionsCreated;
    private int functionSymbolsUpdated;
    private int secondaryVtableFunctionCount;
    private int globalFunctionCount;
    private int skippedFunctionCount;
    private int malformedVtableEntryCount;
    private int inheritedPlaceholderCount;
    private int recoveredClassTypeCount;
    private int recoveredVtableClassCount;
    private int recoveredVtableCount;
    private int updatedVtableDefinitionCount;
    private int renamedVtableFieldCount;
    private int failedVtableDefinitionCount;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open the target program before running this script.");
        }

        File xmlFile = chooseXmlFile();
        Document document = readXml(xmlFile);
        Element root = document.getDocumentElement();

        if (!"Data".equals(root.getTagName())) {
            throw new IllegalArgumentException("Expected a <Data> root element in " + xmlFile);
        }

        symbolTable = currentProgram.getSymbolTable();
        dataTypeManager = currentProgram.getDataTypeManager();
        memory = currentProgram.getMemory();
        addressSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        pointerSize = currentProgram.getDefaultPointerSize();
        namespaces.put("", currentProgram.getGlobalNamespace());

        indexRecoveredClassDataTypes();

        List<Element> classes = childElements(child(root, "Classes"), "Class");
        List<Element> globalFunctions = childElements(child(root, "Functions"), "Function");
        monitor.initialize(classes.size() * 2L + globalFunctions.size());
        monitor.setMessage("Creating SymbolWeave classes");

        // Create every class and placeholder datatype before resolving signatures.
        for (Element classElement : classes) {
            monitor.checkCancelled();
            String className = attribute(classElement, "name", "");
            if (!className.isEmpty()) {
                ensureClass(className);
                ensureClassDataType(className);
                classCount++;
            }
            monitor.incrementProgress(1);
        }

        monitor.setMessage("Importing SymbolWeave vtables and functions");
        for (Element classElement : classes) {
            monitor.checkCancelled();
            importClass(classElement);
            monitor.incrementProgress(1);
        }

        // Global/loose functions live directly below Data/Functions.
        monitor.setMessage("Importing SymbolWeave global functions");
        for (Element functionElement : globalFunctions) {
            monitor.checkCancelled();
            int importedBefore = functionCount;
            importDirectFunction(functionElement, null);
            if (functionCount > importedBefore) globalFunctionCount++;
            monitor.incrementProgress(1);
        }

        updateRecoveredClassDataTypes(classes);
        printSummary(xmlFile);
    }

    private File chooseXmlFile() throws Exception {
        String[] args = getScriptArgs();
        java.nio.file.Path config = null;
        if (args.length > 0 && (args[0].equals("-c") || args[0].equals("--config"))) {
            if (args.length < 2)
                throw new IllegalArgumentException("-c requires a configuration file");
            config = java.nio.file.Path.of(args[1]).toAbsolutePath();
        } else if (args.length > 0 && !args[0].isBlank()) {
            File file = new File(args[0]);
            if (!file.isFile())
                throw new IllegalArgumentException("SDK XML does not exist: " + file);
            return file;
        } else {
            java.nio.file.Path start = java.nio.file.Path.of("").toAbsolutePath();
            config = findConfig(start);
            if (config == null && getSourceFile() != null)
                config =
                        findConfig(
                                java.nio.file.Path.of(getSourceFile().getAbsolutePath())
                                        .getParent());
        }
        if (config != null) {
            com.google.gson.JsonObject root;
            try (var reader = java.nio.file.Files.newBufferedReader(config)) {
                root = com.google.gson.JsonParser.parseReader(reader).getAsJsonObject();
            }
            var outputs =
                    root.has("outputs")
                            ? root.getAsJsonObject("outputs")
                            : new com.google.gson.JsonObject();
            if (outputs.has("importerCategory"))
                DATA_TYPE_ROOT = outputs.get("importerCategory").getAsString();
            String path =
                    outputs.has("xml")
                            ? outputs.get("xml").getAsString()
                            : "build/metadata/merged.xml";
            java.util.regex.Matcher variables =
                    java.util.regex.Pattern.compile("\\$\\{([^}]+)}").matcher(path);
            StringBuilder expanded = new StringBuilder();
            while (variables.find()) {
                String value = System.getenv(variables.group(1));
                if (value == null)
                    throw new IllegalArgumentException(
                            "Missing environment variable: " + variables.group(1));
                variables.appendReplacement(
                        expanded, java.util.regex.Matcher.quoteReplacement(value));
            }
            variables.appendTail(expanded);
            File file = config.getParent().resolve(expanded.toString()).normalize().toFile();
            if (!file.isFile())
                throw new IllegalArgumentException("Configured SDK XML does not exist: " + file);
            return file;
        }
        if (DEFAULT_XML_FILE.isFile()) {
            return DEFAULT_XML_FILE;
        }
        if (getSourceFile() != null) {
            File scriptFile = new File(getSourceFile().getAbsolutePath());
            File scriptDirectory = scriptFile.getParentFile();
            File repositoryDirectory =
                    scriptDirectory == null ? null : scriptDirectory.getParentFile();
            if (repositoryDirectory != null) {
                File repositoryDefault = new File(repositoryDirectory, "build/metadata/merged.xml");
                if (repositoryDefault.isFile()) {
                    return repositoryDefault;
                }
            }
        }
        return askFile("Select SDK metadata XML", "Import");
    }

    private java.nio.file.Path findConfig(java.nio.file.Path start) {
        for (var directory = start; directory != null; directory = directory.getParent()) {
            var candidate = directory.resolve("config.json");
            if (java.nio.file.Files.isRegularFile(candidate)) return candidate;
        }
        return null;
    }

    private Document readXml(File file) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setAttribute(
                    "http://www.oracle.com/xml/jaxp/properties/maxGeneralEntitySizeLimit", 0);
            factory.setAttribute(
                    "http://www.oracle.com/xml/jaxp/properties/totalEntitySizeLimit", 0);
        } catch (IllegalArgumentException ignored) {
            // Older Ghidra Java runtimes may not expose all JAXP attributes.
        }
        return factory.newDocumentBuilder().parse(file);
    }

    private void importClass(Element classElement) throws Exception {
        String className = attribute(classElement, "name", "");
        Namespace classNamespace = namespaces.get(className);
        if (classNamespace == null) {
            return;
        }

        Address vtableAddress = decodeAddress(attribute(classElement, "address", "0"));
        int declaredVtableCount = decodeInt(attribute(classElement, "vtableCount", "0"), 0);

        if (isMapped(vtableAddress)) {
            labelVtable(classElement, classNamespace, vtableAddress, declaredVtableCount);
        }

        Element functions = child(classElement, "Functions");
        if (functions == null) {
            return;
        }

        for (Element functionElement : childElements(functions, null)) {
            monitor.checkCancelled();
            if ("VirtualFunction".equals(functionElement.getTagName())) {
                int index = decodeInt(attribute(functionElement, "index", "-1"), -1);
                if (index < 0) {
                    malformedVtableEntryCount++;
                    skippedFunctionCount++;
                    continue;
                }

                Address declaredSlotAddress =
                        decodeAddress(attribute(functionElement, "address", "0"));
                String functionName = attribute(functionElement, "name", "");
                if (!isMapped(declaredSlotAddress)
                        && isInheritedPlaceholder(className, functionName)) {
                    inheritedPlaceholderCount++;
                    skippedFunctionCount++;
                    continue;
                }

                Address functionAddress =
                        resolveVirtualFunction(
                                functionElement, vtableAddress, index, declaredVtableCount);
                int importedBefore = functionCount;
                importFunction(functionElement, functionAddress, classNamespace);
                if (functionCount > importedBefore
                        && declaredVtableCount > 0
                        && index >= declaredVtableCount) {
                    secondaryVtableFunctionCount++;
                }
            } else if ("Function".equals(functionElement.getTagName())) {
                importDirectFunction(functionElement, classNamespace);
            }
        }
    }

    private void labelVtable(
            Element classElement, Namespace classNamespace, Address address, int count) {
        try {
            if (symbolTable.getSymbol("vftable", address, classNamespace) == null) {
                symbolTable.createLabel(address, "vftable", classNamespace, SourceType.IMPORTED);
                vtableLabelsCreated++;
            }

            StringBuilder comment = new StringBuilder("SymbolWeave vtable");
            if (count > 0) {
                comment.append(" (").append(count).append(" slots)");
            }

            Element inheritance = child(classElement, "Inheritance");
            List<Element> parents = childElements(inheritance, "Parent");
            if (!parents.isEmpty()) {
                comment.append("\nParents: ");
                for (int i = 0; i < parents.size(); i++) {
                    if (i != 0) comment.append(", ");
                    comment.append(attribute(parents.get(i), "name", ""));
                }
            }

            currentProgram
                    .getListing()
                    .setComment(
                            address,
                            ghidra.program.model.listing.CommentType.PLATE,
                            comment.toString());
            vtableCount++;
        } catch (Exception e) {
            recordFailure("Could not label vtable at " + address, e);
        }
    }

    private Address resolveVirtualFunction(
            Element functionElement, Address vtableAddress, int index, int declaredVtableCount) {
        try {
            if (index < 0) {
                return null;
            }
            // Merged XML lists every virtual method and stores the address of its vtable slot.
            // Fall back to class-vtable + index only for older/zero-address entries.
            Address slotAddress = decodeAddress(attribute(functionElement, "address", "0"));
            if (!isMapped(slotAddress)
                    && isMapped(vtableAddress)
                    && index >= 0
                    && (declaredVtableCount <= 0 || index < declaredVtableCount)) {
                slotAddress = vtableAddress.add((long) index * pointerSize);
            }
            if (!isMapped(slotAddress)) {
                return null;
            }
            long pointer =
                    pointerSize == 8
                            ? memory.getLong(slotAddress)
                            : Integer.toUnsignedLong(memory.getInt(slotAddress));
            if (pointer == 0) {
                return null;
            }
            Address functionAddress = addressSpace.getAddress(pointer);
            return isMapped(functionAddress) ? functionAddress : null;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isInheritedPlaceholder(String className, String functionName) {
        if (functionName.isEmpty() || "undefined".equals(functionName)) {
            return false;
        }
        List<String> parts = splitQualifiedName(functionName);
        if (parts.size() < 2) {
            return false;
        }
        String ownerName = join(parts.subList(0, parts.size() - 1));
        return !ownerName.equals(className);
    }

    private void indexRecoveredClassDataTypes() throws Exception {
        List<Structure> recoveredClasses = new ArrayList<>();
        var structures = dataTypeManager.getAllStructures();
        while (structures.hasNext()) {
            monitor.checkCancelled();
            Structure structure = structures.next();
            String categoryPath = structure.getCategoryPath().getPath();
            if (!categoryPath.startsWith("/ClassDataTypes/")) {
                continue;
            }

            String qualifiedName =
                    categoryPath.substring("/ClassDataTypes/".length()).replace("/", "::");
            if (structure.getName().equals(simpleName(qualifiedName))) {
                classTypes.put(qualifiedName, structure);
                recoveredClasses.add(structure);
                recoveredClassTypeCount++;
            }
        }

        for (Structure recoveredClass : recoveredClasses) {
            monitor.checkCancelled();
            ensureOwnClassDataRow(recoveredClass);
        }
    }

    private void ensureOwnClassDataRow(Structure recoveredClass) {
        String dataName = recoveredClass.getName() + "_data";
        CategoryPath categoryPath = recoveredClass.getCategoryPath();
        try {
            DataType dataType = dataTypeManager.getDataType(categoryPath, dataName);
            if (dataType == null) {
                dataType =
                        dataTypeManager.resolve(
                                new StructureDataType(categoryPath, dataName, 0),
                                DataTypeConflictHandler.KEEP_HANDLER);
            }
            if (!(dataType instanceof Structure ownData)) {
                throw new IllegalStateException(dataName + " is not a structure");
            }

            for (DataTypeComponent component : recoveredClass.getDefinedComponents()) {
                if (dataName.equals(component.getFieldName())
                        || ownData.getPathName().equals(component.getDataType().getPathName())) {
                    return;
                }
            }

            // A zero-length component documents that this class contributes no instance bytes.
            // Appending it keeps every inherited member and vftable pointer at its recovered
            // offset.
            recoveredClass.add(ownData, 0, dataName, "Empty data contributed by this class");
        } catch (Exception e) {
            recordFailure("Could not add own data row to " + recoveredClass.getPathName(), e);
        }
    }

    private void updateRecoveredClassDataTypes(List<Element> classes) throws Exception {
        Map<String, List<Structure>> vftableCandidatesByClass = new HashMap<>();
        Map<String, List<Structure>> vftablesByClass = new HashMap<>();
        var structures = dataTypeManager.getAllStructures();
        while (structures.hasNext()) {
            monitor.checkCancelled();
            Structure structure = structures.next();
            String categoryPath = structure.getCategoryPath().getPath();
            if (!categoryPath.startsWith("/ClassDataTypes/")
                    || !structure.getName().contains("_vftable")) {
                continue;
            }
            String className =
                    categoryPath.substring("/ClassDataTypes/".length()).replace("/", "::");
            if (!structure.getName().startsWith(simpleName(className) + "_vftable")) {
                continue;
            }
            vftableCandidatesByClass
                    .computeIfAbsent(className, ignored -> new ArrayList<>())
                    .add(structure);
        }

        for (Map.Entry<String, List<Structure>> entry : vftableCandidatesByClass.entrySet()) {
            List<Structure> ordered = orderRecoveredVftables(entry.getKey(), entry.getValue());
            if (!ordered.isEmpty()) {
                vftablesByClass.put(entry.getKey(), ordered);
            }
        }

        if (vftablesByClass.isEmpty()) {
            return;
        }

        monitor.setMessage("Updating recovered ClassDataTypes definitions");
        recoveredVtableClassCount = vftablesByClass.size();
        recoveredVtableCount = vftablesByClass.values().stream().mapToInt(List::size).sum();

        for (Element classElement : classes) {
            monitor.checkCancelled();
            String className = attribute(classElement, "name", "");
            List<Structure> classVftables = vftablesByClass.get(className);
            if (classVftables == null || classVftables.isEmpty()) {
                continue;
            }

            Element functions = child(classElement, "Functions");
            for (Element functionElement : childElements(functions, "VirtualFunction")) {
                monitor.checkCancelled();
                int index = decodeInt(attribute(functionElement, "index", "-1"), -1);
                String qualifiedName = attribute(functionElement, "name", "");
                if (index < 0 || qualifiedName.isEmpty() || "undefined".equals(qualifiedName)) {
                    continue;
                }
                String simpleName = simpleName(qualifiedName);

                RecoveredVtableSlot recoveredSlot =
                        findRecoveredVtableSlot(functionElement, classVftables, index);
                if (recoveredSlot == null) {
                    continue;
                }
                updateRecoveredVtableSlot(recoveredSlot, functionElement, simpleName);
            }
        }
    }

    private List<Structure> orderRecoveredVftables(String className, List<Structure> candidates) {
        Structure primary = findPrimaryRecoveredVftable(className, candidates);
        if (primary == null) {
            return List.of();
        }

        List<Structure> ordered = new ArrayList<>();
        ordered.add(primary);
        candidates.stream()
                .filter(candidate -> candidate != primary)
                .sorted(
                        Comparator.comparingInt(this::vftableOrdinal)
                                .thenComparing(Structure::getName))
                .forEach(ordered::add);
        return ordered;
    }

    private int vftableOrdinal(Structure vftable) {
        String name = vftable.getName();
        int marker = name.lastIndexOf("_vftable_");
        if (marker < 0) return Integer.MAX_VALUE;
        try {
            return Integer.parseInt(name.substring(marker + "_vftable_".length()));
        } catch (NumberFormatException ignored) {
            return Integer.MAX_VALUE;
        }
    }

    private RecoveredVtableSlot findRecoveredVtableSlot(
            Element functionElement, List<Structure> classVftables, int logicalIndex) {
        Address slotAddress = decodeAddress(attribute(functionElement, "address", "0"));
        RecoveredVtableSlot exact = findRecoveredVtableSlotAtAddress(slotAddress, classVftables);
        if (exact != null) {
            return exact;
        }

        int tableStart = 0;
        for (Structure vftable : classVftables) {
            int localIndex = logicalIndex - tableStart;
            if (localIndex >= 0 && localIndex < vftable.getNumComponents()) {
                return new RecoveredVtableSlot(vftable, localIndex);
            }
            tableStart += vftable.getNumComponents();
        }
        return null;
    }

    private RecoveredVtableSlot findRecoveredVtableSlotAtAddress(
            Address slotAddress, List<Structure> candidates) {
        if (!isMapped(slotAddress)) return null;

        Data containing = currentProgram.getListing().getDataContaining(slotAddress);
        if (containing == null) return null;

        Data current = containing.getRoot();
        while (current != null) {
            if (current.getDataType() instanceof Structure structure
                    && containsDataType(candidates, structure)) {
                long offset = slotAddress.subtract(current.getAddress());
                if (offset >= 0 && offset <= Integer.MAX_VALUE) {
                    DataTypeComponent component = structure.getComponentAt((int) offset);
                    if (component != null) {
                        return new RecoveredVtableSlot(structure, component.getOrdinal());
                    }
                }
            }

            long offset = slotAddress.subtract(current.getAddress());
            if (offset < 0 || offset > Integer.MAX_VALUE) break;
            Data next = current.getComponentContaining((int) offset);
            if (next == null || next == current) break;
            current = next;
        }
        return null;
    }

    private boolean containsDataType(List<Structure> candidates, Structure target) {
        return candidates.stream()
                .anyMatch(candidate -> candidate.getPathName().equals(target.getPathName()));
    }

    private void updateRecoveredVtableSlot(
            RecoveredVtableSlot recoveredSlot, Element functionElement, String simpleName) {
        Structure vftable = recoveredSlot.vftable();
        int index = recoveredSlot.index();
        try {
            DataTypeComponent component = vftable.getComponent(index);
            DataType componentType = component.getDataType();
            if (!(componentType instanceof Pointer pointer)
                    || !(pointer.getDataType() instanceof FunctionDefinition definition)) {
                return;
            }

            FunctionDefinition targetDefinition =
                    getOrCreateFunctionDefinition(definition, simpleName);
            updateFunctionDefinition(targetDefinition, definition, functionElement);
            updatedVtableDefinitionCount++;
            if (targetDefinition != definition || !simpleName.equals(component.getFieldName())) {
                Pointer targetPointer =
                        dataTypeManager.getPointer(targetDefinition, component.getLength());
                vftable.replace(
                        index,
                        targetPointer,
                        component.getLength(),
                        simpleName,
                        component.getComment());
                renamedVtableFieldCount++;
            }
        } catch (Exception e) {
            failedVtableDefinitionCount++;
            recordFailure(
                    "Could not update recovered datatype "
                            + vftable.getPathName()
                            + " slot "
                            + index,
                    e);
        }
    }

    private record RecoveredVtableSlot(Structure vftable, int index) {}

    private Structure findPrimaryRecoveredVftable(String className, List<Structure> candidates) {
        if (candidates.size() == 1) {
            return candidates.get(0);
        }

        DataType recoveredClass = classTypes.get(className);
        if (!(recoveredClass instanceof Structure classStructure)) {
            return null;
        }
        DataTypeComponent firstComponent = classStructure.getComponentAt(0);
        if (firstComponent == null
                || !(firstComponent.getDataType() instanceof Pointer pointer)
                || !(pointer.getDataType() instanceof Structure pointedVftable)) {
            return null;
        }

        for (Structure candidate : candidates) {
            if (candidate.getPathName().equals(pointedVftable.getPathName())) {
                return candidate;
            }
        }
        return null;
    }

    private FunctionDefinition getOrCreateFunctionDefinition(
            FunctionDefinition source, String desiredName) {
        if (desiredName.equals(source.getName())) {
            return source;
        }

        DataType existing = dataTypeManager.getDataType(source.getCategoryPath(), desiredName);
        if (existing instanceof FunctionDefinition definition) {
            return definition;
        }

        FunctionDefinitionDataType candidate =
                new FunctionDefinitionDataType(source.getCategoryPath(), desiredName, source);
        DataType resolved =
                dataTypeManager.resolve(candidate, DataTypeConflictHandler.KEEP_HANDLER);
        if (resolved instanceof FunctionDefinition definition) {
            return definition;
        }
        throw new IllegalStateException(
                "Could not create function definition "
                        + desiredName
                        + " in "
                        + source.getCategoryPath());
    }

    private void updateFunctionDefinition(
            FunctionDefinition definition,
            FunctionDefinition sourceDefinition,
            Element functionElement)
            throws Exception {

        Element returnElement = child(functionElement, "ReturnType");
        if (returnElement != null) {
            definition.setReturnType(resolveType(returnElement));
        }

        List<ParameterDefinition> parameters = new ArrayList<>();
        ParameterDefinition[] existingParameters = definition.getArguments();
        if (existingParameters.length > 0 && "this".equals(existingParameters[0].getName())) {
            parameters.add(existingParameters[0]);
        } else {
            ParameterDefinition[] sourceParameters = sourceDefinition.getArguments();
            if (sourceParameters.length > 0 && "this".equals(sourceParameters[0].getName())) {
                parameters.add(sourceParameters[0]);
            }
        }
        List<Element> parameterElements = childElements(functionElement, "Parameter");
        for (Element parameterElement : parameterElements) {
            DataType type = resolveType(parameterElement);
            if (type instanceof VoidDataType && parameterElements.size() == 1) {
                continue;
            }
            String parameterName = attribute(parameterElement, "name", "param" + parameters.size());
            parameters.add(new ParameterDefinitionImpl(parameterName, type, null));
        }
        definition.setArguments(parameters.toArray(ParameterDefinition[]::new));

        String convention = attribute(functionElement, "callingConvention", "");
        if (!convention.isEmpty()) {
            try {
                definition.setCallingConvention(convention);
            } catch (Exception ignored) {
                // x64 compiler specifications may not expose __thiscall separately.
            }
        }
    }

    private void importDirectFunction(Element functionElement, Namespace fallbackNamespace) {
        Address address = decodeAddress(attribute(functionElement, "address", "0"));
        importFunction(functionElement, address, fallbackNamespace);
    }

    private void importFunction(
            Element functionElement, Address address, Namespace fallbackNamespace) {
        String qualifiedName = attribute(functionElement, "name", "");
        if (qualifiedName.isEmpty() || "undefined".equals(qualifiedName) || !isMapped(address)) {
            skippedFunctionCount++;
            return;
        }

        List<String> nameParts = splitQualifiedName(qualifiedName);
        String simpleName = nameParts.get(nameParts.size() - 1);
        String ownerName = join(nameParts.subList(0, nameParts.size() - 1));
        Namespace owner = ownerName.isEmpty() ? fallbackNamespace : ensureNamespace(ownerName);
        if (owner == null) owner = currentProgram.getGlobalNamespace();

        try {
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            boolean created = false;
            if (function == null) {
                disassemble(address);
                function = createFunction(address, simpleName);
                created = function != null;
            }
            if (function == null) {
                skippedFunctionCount++;
                failures.add("Could not create function " + qualifiedName + " at " + address);
                return;
            }

            boolean symbolUpdated = !simpleName.equals(function.getName());
            if (owner != null && function.getParentNamespace().getID() != owner.getID()) {
                function.setParentNamespace(owner);
                symbolUpdated = true;
            }
            function.setName(simpleName, SourceType.IMPORTED);
            applySignature(function, functionElement);
            functionCount++;
            if (created) functionsCreated++;
            else if (symbolUpdated) functionSymbolsUpdated++;
        } catch (Exception e) {
            skippedFunctionCount++;
            recordFailure("Could not import " + qualifiedName + " at " + address, e);
        }
    }

    private void applySignature(Function function, Element functionElement) throws Exception {
        String convention = attribute(functionElement, "callingConvention", "");
        if (!convention.isEmpty()) {
            try {
                function.setCallingConvention(convention);
            } catch (Exception ignored) {
                // For example, x64 compiler specs may not expose __thiscall separately.
            }
        }

        Element returnElement = child(functionElement, "ReturnType");
        if (returnElement != null) {
            function.setReturnType(resolveType(returnElement), SourceType.IMPORTED);
        }

        List<Variable> parameters = new ArrayList<>();
        for (Element parameterElement : childElements(functionElement, "Parameter")) {
            DataType type = resolveType(parameterElement);
            if (type instanceof VoidDataType
                    && parameters.isEmpty()
                    && childElements(functionElement, "Parameter").size() == 1) {
                continue;
            }
            String parameterName = attribute(parameterElement, "name", "param" + parameters.size());
            parameters.add(
                    new ParameterImpl(parameterName, type, currentProgram, SourceType.IMPORTED));
        }

        function.replaceParameters(
                parameters,
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true,
                SourceType.IMPORTED);
    }

    private DataType resolveType(Element typeElement) {
        String baseName = attribute(typeElement, "type", "undefined4").trim();
        String decorations =
                attribute(typeElement, "prefix", "") + attribute(typeElement, "suffix", "");

        DataType type = primitiveType(baseName);
        if (type == null) type = classTypes.get(baseName);
        if (type == null) {
            List<DataType> matches = new ArrayList<>();
            dataTypeManager.findDataTypes(simpleName(baseName), matches, false, monitor);
            if (!matches.isEmpty()) type = matches.get(0);
        }
        if (type == null) type = Undefined4DataType.dataType;

        int indirections = 0;
        for (int i = 0; i < decorations.length(); i++) {
            char c = decorations.charAt(i);
            if (c == '*' || c == '&') indirections++;
        }
        if (baseName.startsWith("FuncDef") && indirections == 0) indirections = 1;

        for (int i = 0; i < indirections; i++) {
            type = new PointerDataType(type, dataTypeManager);
        }
        return type;
    }

    private DataType primitiveType(String name) {
        String normalized = name.replace("std::", "").trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "void" -> VoidDataType.dataType;
            case "bool", "boolean" -> BooleanDataType.dataType;
            case "char", "int8_t" -> CharDataType.dataType;
            case "signed char" -> SignedCharDataType.dataType;
            case "unsigned char", "uint8_t", "byte" -> UnsignedCharDataType.dataType;
            case "short", "short int", "int16_t" -> ShortDataType.dataType;
            case "unsigned short", "unsigned short int", "uint16_t" ->
                    UnsignedShortDataType.dataType;
            case "int", "signed int", "int32_t" -> IntegerDataType.dataType;
            case "unsigned", "unsigned int", "uint32_t" -> UnsignedIntegerDataType.dataType;
            case "long", "signed long" -> LongDataType.dataType;
            case "unsigned long" -> UnsignedLongDataType.dataType;
            case "long long", "signed long long", "int64_t" -> LongLongDataType.dataType;
            case "unsigned long long", "uint64_t" -> UnsignedLongLongDataType.dataType;
            case "float" -> FloatDataType.dataType;
            case "double" -> DoubleDataType.dataType;
            case "wchar_t" -> WideCharDataType.dataType;
            case "uintptr_t", "size_t" ->
                    pointerSize == 8
                            ? UnsignedLongLongDataType.dataType
                            : UnsignedIntegerDataType.dataType;
            case "undefined", "undefined1" -> Undefined1DataType.dataType;
            case "undefined2" -> Undefined2DataType.dataType;
            case "undefined4" -> Undefined4DataType.dataType;
            case "undefined8" -> Undefined8DataType.dataType;
            default -> null;
        };
    }

    private Namespace ensureClass(String qualifiedName) {
        Namespace existing = namespaces.get(qualifiedName);
        if (existing != null) return existing;

        List<String> parts = splitQualifiedName(qualifiedName);
        Namespace parent = ensureNamespace(join(parts.subList(0, parts.size() - 1)));
        String className = parts.get(parts.size() - 1);

        try {
            Symbol classSymbol = symbolTable.getClassSymbol(className, parent);
            Namespace result;
            if (classSymbol != null && classSymbol.getObject() instanceof Namespace namespace) {
                result = namespace;
            } else {
                Namespace ordinaryNamespace = symbolTable.getNamespace(className, parent);
                if (ordinaryNamespace != null) {
                    result = ordinaryNamespace;
                } else {
                    GhidraClass created =
                            symbolTable.createClass(parent, className, SourceType.IMPORTED);
                    result = created;
                }
            }
            namespaces.put(qualifiedName, result);
            return result;
        } catch (Exception e) {
            recordFailure("Could not create class namespace " + qualifiedName, e);
            return parent;
        }
    }

    private Namespace ensureNamespace(String qualifiedName) {
        if (qualifiedName == null || qualifiedName.isEmpty()) {
            return currentProgram.getGlobalNamespace();
        }
        Namespace cached = namespaces.get(qualifiedName);
        if (cached != null) return cached;

        Namespace current = currentProgram.getGlobalNamespace();
        StringBuilder fullName = new StringBuilder();
        for (String part : splitQualifiedName(qualifiedName)) {
            if (fullName.length() != 0) fullName.append("::");
            fullName.append(part);
            Namespace known = namespaces.get(fullName.toString());
            if (known != null) {
                current = known;
                continue;
            }
            try {
                Namespace next = symbolTable.getNamespace(part, current);
                if (next == null) {
                    next = symbolTable.createNameSpace(current, part, SourceType.IMPORTED);
                }
                current = next;
                namespaces.put(fullName.toString(), current);
            } catch (Exception e) {
                recordFailure("Could not create namespace " + fullName, e);
                return current;
            }
        }
        return current;
    }

    private void ensureClassDataType(String qualifiedName) {
        if (classTypes.containsKey(qualifiedName)) return;
        List<String> parts = splitQualifiedName(qualifiedName);
        String typeName = parts.get(parts.size() - 1);
        StringBuilder category = new StringBuilder(DATA_TYPE_ROOT);
        for (int i = 0; i < parts.size() - 1; i++) {
            category.append('/').append(parts.get(i).replace('/', '_'));
        }
        try {
            CategoryPath categoryPath = new CategoryPath(category.toString());
            DataType existing = dataTypeManager.getDataType(categoryPath, typeName);
            if (existing == null) {
                existing =
                        dataTypeManager.resolve(
                                new StructureDataType(categoryPath, typeName, 0),
                                DataTypeConflictHandler.KEEP_HANDLER);
            }
            classTypes.put(qualifiedName, existing);
        } catch (Exception e) {
            recordFailure("Could not create datatype " + qualifiedName, e);
        }
    }

    private Address decodeAddress(String value) {
        try {
            String digits =
                    value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
            if (digits.isEmpty()) return null;
            return addressSpace.getAddress(Long.parseUnsignedLong(digits, 16));
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isMapped(Address address) {
        return address != null && memory.contains(address);
    }

    private static int decodeInt(String value, int defaultValue) {
        try {
            return Integer.decode(value);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private static String formatXmlType(Element element) {
        StringBuilder result = new StringBuilder();
        if (Boolean.parseBoolean(attribute(element, "isConst", "false"))) result.append("const ");
        result.append(attribute(element, "prefix", ""));
        result.append(attribute(element, "type", "undefined"));
        result.append(attribute(element, "suffix", ""));
        return result.toString();
    }

    private static String simpleName(String qualifiedName) {
        List<String> parts = splitQualifiedName(qualifiedName);
        return parts.isEmpty() ? qualifiedName : parts.get(parts.size() - 1);
    }

    private static List<String> splitQualifiedName(String name) {
        List<String> parts = new ArrayList<>();
        int templateDepth = 0;
        int start = 0;
        for (int i = 0; i < name.length() - 1; i++) {
            char c = name.charAt(i);
            if (c == '<') templateDepth++;
            else if (c == '>' && templateDepth > 0) templateDepth--;
            else if (c == ':' && name.charAt(i + 1) == ':' && templateDepth == 0) {
                parts.add(name.substring(start, i));
                start = i + 2;
                i++;
            }
        }
        parts.add(name.substring(start));
        return parts;
    }

    private static String join(List<String> parts) {
        return String.join("::", parts);
    }

    private static String attribute(Element element, String name, String defaultValue) {
        if (element == null || !element.hasAttribute(name)) return defaultValue;
        String value = element.getAttribute(name);
        return value.isEmpty() ? defaultValue : value;
    }

    private static Element child(Element parent, String name) {
        if (parent == null) return null;
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element element && name.equals(element.getTagName()))
                return element;
        }
        return null;
    }

    private static List<Element> childElements(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        if (parent == null) return result;
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element element
                    && (name == null || name.equals(element.getTagName()))) {
                result.add(element);
            }
        }
        return result;
    }

    private void recordFailure(String context, Exception exception) {
        String message = exception.getMessage();
        failures.add(context + (message == null || message.isBlank() ? "" : ": " + message));
    }

    private void printSummary(File xmlFile) {
        int unresolvedFunctions =
                Math.max(
                        0,
                        skippedFunctionCount
                                - inheritedPlaceholderCount
                                - malformedVtableEntryCount);

        println("");
        println("SymbolWeave import complete");
        println("  Program: " + currentProgram.getName());
        println("  Source: " + xmlFile.getAbsolutePath());
        println(
                "  Classes: "
                        + classCount
                        + " processed; "
                        + recoveredClassTypeCount
                        + " existing RTTI class datatypes reused");
        println(
                "  Vtables: "
                        + vtableCount
                        + " annotated; "
                        + vtableLabelsCreated
                        + " labels created");
        println(
                "  Functions: "
                        + functionCount
                        + " signatures applied; "
                        + functionsCreated
                        + " created; "
                        + functionSymbolsUpdated
                        + " existing symbols renamed; "
                        + globalFunctionCount
                        + " globals; "
                        + secondaryVtableFunctionCount
                        + " secondary-table entries");
        println(
                "  Recovered RTTI vtables: "
                        + recoveredVtableClassCount
                        + " classes / "
                        + recoveredVtableCount
                        + " tables matched; "
                        + updatedVtableDefinitionCount
                        + " definitions updated; "
                        + renamedVtableFieldCount
                        + " fields renamed");
        println(
                "  Skipped: "
                        + skippedFunctionCount
                        + " functions ("
                        + unresolvedFunctions
                        + " unresolved or unmapped; "
                        + inheritedPlaceholderCount
                        + " inherited placeholders; "
                        + malformedVtableEntryCount
                        + " malformed entries)");
        println(
                "  Issues: "
                        + failures.size()
                        + " recoverable; "
                        + failedVtableDefinitionCount
                        + " while updating recovered vtable definitions");

        if (!failures.isEmpty()) {
            printerr("First " + Math.min(20, failures.size()) + " issue(s):");
            for (int i = 0; i < Math.min(20, failures.size()); i++) {
                printerr("  " + failures.get(i));
            }
            if (failures.size() > 20) {
                printerr("  ... " + (failures.size() - 20) + " more");
            }
        }
    }
}
