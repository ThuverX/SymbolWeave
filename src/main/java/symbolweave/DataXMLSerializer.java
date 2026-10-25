package symbolweave;

import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaders;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.MemberContainer;
import symbolweave.containers.ParameterContainer;
import symbolweave.containers.TypeContainer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DataXMLSerializer {

    public static void serialize(FileContainer fc, XmlWriter writer) {
        XmlAttributes attributes = new XmlAttributes();
        attributes.addAttribute("generatedFor", fc.getGeneratedFor());
        writer.startElement("Data", attributes);

        if (fc.getClasses().size() > 0) {
            writer.startElement("Classes");

            for (ClassContainer aClass : fc.getClasses()) {
                serializeClassContainer(aClass, writer);
            }

            writer.endElement("Classes");
        }

        if (fc.getLooseFunctions().size() > 0) {
            writer.startElement("Functions");

            for (FunctionContainer fn : fc.getLooseFunctions()) {
                XmlAttributes functionAttributes = new XmlAttributes();
                functionAttributes.addAttribute("address", String.format("0x%X", fn.getAddress()));

                if (!fn.getCallingConvention().toString().isEmpty()) {
                    functionAttributes.addAttribute(
                            "callingConvention", fn.getCallingConvention().getName());
                }

                functionAttributes.addAttribute("name", fn.getName().toString());

                if (!fn.getHeaderFile().isEmpty()) {
                    functionAttributes.addAttribute("headerFile", fn.getHeaderFile());
                }

                if (fn.isOverride()) {
                    functionAttributes.addAttribute("isOverride", String.valueOf(fn.isOverride()));
                }

                if (fn.isStatic()) {
                    functionAttributes.addAttribute("isStatic", String.valueOf(fn.isStatic()));
                }

                if (fn.isVarargs()) {
                    functionAttributes.addAttribute("isVarargs", String.valueOf(fn.isVarargs()));
                }

                writeFunctionAnalysisAttributes(fn, functionAttributes);

                writer.startElement("Function", functionAttributes);

                writeReturnTypeContainer(fn.getReturnType(), writer);

                if (fn.getParameters().size() > 0) {
                    for (Map.Entry<Integer, ParameterContainer> parameterContainerEntry :
                            fn.getParameters().entrySet()) {
                        writeParameterContainer(
                                parameterContainerEntry.getKey(),
                                parameterContainerEntry.getValue(),
                                writer);
                    }
                }

                writer.endElement("Function");
            }

            writer.endElement("Functions");
        }

        writer.endElement("Data");
    }

    private static void serializeClassContainer(ClassContainer cc, XmlWriter writer) {
        XmlAttributes classAttributes = new XmlAttributes();
        classAttributes.addAttribute("name", cc.getName().toString());
        classAttributes.addAttribute("address", String.format("0x%X", cc.getVtableAddress()));
        classAttributes.addAttribute("vtableCount", String.valueOf(cc.getVtableCount()));

        writer.startElement("Class", classAttributes);

        if (cc.getParents().size() > 0) {
            writer.startElement("Inheritance");
            for (Util.NamespacedString parent : cc.getParents()) {
                XmlAttributes attrs = new XmlAttributes();
                attrs.addAttribute("name", parent.toString());
                writer.writeElement("Parent", attrs);
            }
            writer.endElement("Inheritance");
        }

        if (cc.getVirtualFunctions().size() > 0 || cc.getFunctions().size() > 0) {
            writer.startElement("Functions");

            serializeVtableFunctions(cc.getVirtualFunctions(), writer);
            serializeRegularFunctions(cc.getFunctions(), writer);

            writer.endElement("Functions");
        }

        if (cc.getMembers().size() > 0) {
            writer.startElement("Members");

            for (MemberContainer member : cc.getMembers()) {
                writeMemberContainer(member, writer);
            }

            writer.endElement("Members");
        }

        writer.endElement("Class");
    }

    private static void writeMemberContainer(MemberContainer member, XmlWriter writer) {
        XmlAttributes attributes = new XmlAttributes();

        attributes.addAttribute("name", member.getName());
        attributes.addAttribute("type", member.getType().getName().toString());

        if (!member.getType().getPrefix().isEmpty())
            attributes.addAttribute("prefix", member.getType().getPrefix());

        if (!member.getType().getSuffix().isEmpty())
            attributes.addAttribute("suffix", member.getType().getSuffix());

        if (member.getType().isConst())
            attributes.addAttribute("isConst", String.valueOf(member.getType().isConst()));

        if (member.isStatic())
            attributes.addAttribute("isStatic", String.valueOf(member.isStatic()));

        if (member.getArraySize() > 0)
            attributes.addAttribute("isArray", String.valueOf(member.getArraySize()));

        if (member.getSize() > 0)
            attributes.addAttribute("size", String.format("0x%X", member.getSize()));

        if (member.getOffset() != null)
            attributes.addAttribute("offset", String.format("0x%X", member.getOffset()));

        if (member.getAddress() != null)
            attributes.addAttribute("address", String.format("0x%X", member.getAddress()));

        if (!member.getValue().isEmpty()) {
            attributes.addAttribute("value", member.getValue());
        }

        writer.writeElement("Member", attributes);
    }

    private static void serializeRegularFunctions(
            List<FunctionContainer> functions, XmlWriter writer) {
        for (FunctionContainer fn : functions) {

            XmlAttributes functionAttributes = new XmlAttributes();
            functionAttributes.addAttribute("address", String.format("0x%X", fn.getAddress()));

            if (!fn.getCallingConvention().toString().isEmpty()) {
                functionAttributes.addAttribute(
                        "callingConvention", fn.getCallingConvention().getName());
            }

            functionAttributes.addAttribute("name", fn.getName().toString());

            if (fn.isOverride()) {
                functionAttributes.addAttribute("isOverride", String.valueOf(fn.isOverride()));
            }

            if (fn.isStatic()) {
                functionAttributes.addAttribute("isStatic", String.valueOf(fn.isStatic()));
            }

            if (fn.isVarargs()) {
                functionAttributes.addAttribute("isVarargs", String.valueOf(fn.isVarargs()));
            }

            writeFunctionAnalysisAttributes(fn, functionAttributes);

            writer.startElement("Function", functionAttributes);

            writeReturnTypeContainer(fn.getReturnType(), writer);

            if (fn.getParameters().size() > 0) {
                for (Map.Entry<Integer, ParameterContainer> parameterContainerEntry :
                        fn.getParameters().entrySet()) {
                    writeParameterContainer(
                            parameterContainerEntry.getKey(),
                            parameterContainerEntry.getValue(),
                            writer);
                }
            }

            writer.endElement("Function");
        }
    }

    private static void serializeVtableFunctions(
            Map<Integer, FunctionContainer> vtableFunctions, XmlWriter writer) {
        for (Map.Entry<Integer, FunctionContainer> fnEntry : vtableFunctions.entrySet()) {
            FunctionContainer fn = fnEntry.getValue();
            if (fn == null) {
                XmlAttributes slotAttributes = new XmlAttributes();
                slotAttributes.addAttribute("index", fnEntry.getKey());

                writer.writeElement("VirtualFunction", slotAttributes);

                continue;
            }

            XmlAttributes functionAttributes = new XmlAttributes();
            functionAttributes.addAttribute("index", fnEntry.getKey());
            functionAttributes.addAttribute("address", String.format("0x%X", fn.getAddress()));

            if (!fn.getCallingConvention().toString().isEmpty()) {
                functionAttributes.addAttribute(
                        "callingConvention", fn.getCallingConvention().getName());
            }

            functionAttributes.addAttribute("name", fn.getName().toString());

            if (fn.isOverride()) {
                functionAttributes.addAttribute("isOverride", String.valueOf(fn.isOverride()));
            }

            if (fn.isStatic()) {
                functionAttributes.addAttribute("isStatic", String.valueOf(fn.isStatic()));
            }

            if (fn.isVarargs()) {
                functionAttributes.addAttribute("isVarargs", String.valueOf(fn.isVarargs()));
            }

            writeFunctionAnalysisAttributes(fn, functionAttributes);

            writer.startElement("VirtualFunction", functionAttributes);

            writeReturnTypeContainer(fn.getReturnType(), writer);

            if (fn.getParameters().size() > 0) {
                for (Map.Entry<Integer, ParameterContainer> parameterContainerEntry :
                        fn.getParameters().entrySet()) {
                    writeParameterContainer(
                            parameterContainerEntry.getKey(),
                            parameterContainerEntry.getValue(),
                            writer);
                }
            }

            writer.endElement("VirtualFunction");
        }
    }

    private static void writeReturnTypeContainer(TypeContainer typeContainer, XmlWriter writer) {
        XmlAttributes attributes = new XmlAttributes();

        attributes.addAttribute("type", typeContainer.getName().toString());

        if (!typeContainer.getPrefix().isEmpty())
            attributes.addAttribute("prefix", typeContainer.getPrefix());

        if (!typeContainer.getSuffix().isEmpty())
            attributes.addAttribute("suffix", typeContainer.getSuffix());

        if (typeContainer.isConst())
            attributes.addAttribute("isConst", String.valueOf(typeContainer.isConst()));

        writer.writeElement("ReturnType", attributes);
    }

    private static void writeFunctionAnalysisAttributes(
            FunctionContainer function, XmlAttributes attributes) {
        if (function.hasPureVirtualValue()) {
            attributes.addAttribute("isPureVirtual", String.valueOf(function.isPureVirtual()));
        }
        if (function.getImplementationAddress() != 0) {
            attributes.addAttribute(
                    "implementationAddress",
                    String.format("0x%X", function.getImplementationAddress()));
        }
    }

    private static void writeParameterContainer(
            int index, ParameterContainer parameterContainer, XmlWriter writer) {
        XmlAttributes attributes = new XmlAttributes();

        attributes.addAttribute("index", index);
        attributes.addAttribute("name", parameterContainer.getName());
        attributes.addAttribute("type", parameterContainer.getType().getName().toString());

        if (!parameterContainer.getType().getPrefix().isEmpty())
            attributes.addAttribute("prefix", parameterContainer.getType().getPrefix());

        if (!parameterContainer.getType().getSuffix().isEmpty())
            attributes.addAttribute("suffix", parameterContainer.getType().getSuffix());

        if (parameterContainer.getType().isConst())
            attributes.addAttribute(
                    "isConst", String.valueOf(parameterContainer.getType().isConst()));

        writer.writeElement("Parameter", attributes);
    }

    public static void writeContainerToFile(FileContainer fc, Path outPath) throws IOException {
        XmlWriter writer = new XmlWriter(outPath.toFile(), null);

        serialize(fc, writer);

        writer.close();
    }

    public static FileContainer deserialize(Element element) {
        FileContainer fileContainer = new FileContainer(attribute(element, "generatedFor", ""));
        if (element == null) {
            return fileContainer;
        }

        List<ClassContainer> classes = new ArrayList<>();
        Element classesElement = child(element, "Classes");
        if (classesElement != null) {
            for (Element classElement : children(classesElement, "Class")) {
                classes.add(readClassContainer(classElement));
            }
        }
        fileContainer.setClasses(classes);

        List<FunctionContainer> looseFunctions = new ArrayList<>();
        Element functionsElement = child(element, "Functions");
        if (functionsElement != null) {
            for (Element functionElement : children(functionsElement, "Function")) {
                looseFunctions.add(readFunctionContainer(functionElement));
            }
        }
        fileContainer.setLooseFunctions(looseFunctions);

        return fileContainer;
    }

    private static ClassContainer readClassContainer(Element element) {
        ClassContainer classContainer =
                new ClassContainer(namespaced(attribute(element, "name", "undefined")));
        classContainer.setVtableAddress(longValue(attribute(element, "address", "0"), 0));
        classContainer.setVtableCount(intValue(attribute(element, "vtableCount", "0"), 0));

        List<Util.NamespacedString> parents = new ArrayList<>();
        Element inheritanceElement = child(element, "Inheritance");
        if (inheritanceElement != null) {
            for (Element parentElement : children(inheritanceElement, "Parent")) {
                parents.add(namespaced(attribute(parentElement, "name", "undefined")));
            }
        }
        classContainer.setParents(parents);

        Map<Integer, FunctionContainer> virtualFunctions = new java.util.HashMap<>();
        List<FunctionContainer> functions = new ArrayList<>();
        Element functionsElement = child(element, "Functions");
        if (functionsElement != null) {
            int nextVirtualIndex = 0;
            for (Element functionElement : children(functionsElement, null)) {
                if ("VirtualFunction".equals(functionElement.getName())) {
                    int index = intValue(attribute(functionElement, "index", ""), nextVirtualIndex);
                    nextVirtualIndex = Math.max(nextVirtualIndex, index + 1);
                    virtualFunctions.put(
                            index,
                            hasFunctionData(functionElement)
                                    ? readFunctionContainer(functionElement)
                                    : null);
                } else if ("Function".equals(functionElement.getName())) {
                    functions.add(readFunctionContainer(functionElement));
                }
            }
        }
        classContainer.setVirtualFunctions(virtualFunctions);
        classContainer.setFunctions(functions);

        List<MemberContainer> members = new ArrayList<>();
        Element membersElement = child(element, "Members");
        if (membersElement != null) {
            for (Element memberElement : children(membersElement, "Member")) {
                MemberContainer member = new MemberContainer(attribute(memberElement, "name", ""));
                member.setType(readTypeContainer(memberElement));
                member.setStatic(
                        booleanValue(attribute(memberElement, "isStatic", "false"), false));
                member.setArraySize(longValue(attribute(memberElement, "isArray", "0"), 0));
                member.setValue(attribute(memberElement, "value", ""));
                member.setSize(longValue(attribute(memberElement, "size", "0"), 0));
                member.setOffset(nullableLongValue(memberElement.getAttributeValue("offset")));
                member.setAddress(nullableLongValue(memberElement.getAttributeValue("address")));
                XmlPresence.record(
                        member,
                        memberElement,
                        Map.ofEntries(
                                Map.entry("name", "name"),
                                Map.entry("type", "type"),
                                Map.entry("isStatic", "static"),
                                Map.entry("isArray", "arraySize"),
                                Map.entry("value", "value"),
                                Map.entry("size", "size"),
                                Map.entry("offset", "offset"),
                                Map.entry("address", "address")));
                members.add(member);
            }
        }
        classContainer.setMembers(members);
        XmlPresence.record(
                classContainer,
                element,
                Map.of(
                        "name",
                        "name",
                        "address",
                        "vtableAddress",
                        "vtableCount",
                        "vtableCount",
                        "Inheritance",
                        "parents",
                        "Functions",
                        "functions",
                        "Members",
                        "members"));
        return classContainer;
    }

    private static FunctionContainer readFunctionContainer(Element element) {
        FunctionContainer function =
                new FunctionContainer(namespaced(attribute(element, "name", "undefined")));
        function.setAddress(longValue(attribute(element, "address", "0"), 0));
        function.setHeaderFile(attribute(element, "headerFile", ""));
        function.setOverride(booleanValue(attribute(element, "isOverride", "false"), false));
        function.setStatic(booleanValue(attribute(element, "isStatic", "false"), false));
        function.setVarargs(booleanValue(attribute(element, "isVarargs", "false"), false));
        if (element.getAttribute("isPureVirtual") != null) {
            function.setPureVirtual(
                    booleanValue(attribute(element, "isPureVirtual", "false"), false));
        }
        function.setImplementationAddress(
                longValue(attribute(element, "implementationAddress", "0"), 0));

        String callingConvention = attribute(element, "callingConvention", "");
        if (!callingConvention.isEmpty()) {
            try {
                FunctionContainer.CallingConvention parsedCallingConvention =
                        FunctionContainer.CallingConvention.forName(callingConvention);
                if (parsedCallingConvention != null) {
                    function.setCallingConvention(parsedCallingConvention);
                }
            } catch (RuntimeException ignored) {
            }
        }

        Element returnTypeElement = child(element, "ReturnType");
        if (returnTypeElement != null) {
            function.setReturnType(readTypeContainer(returnTypeElement));
        }

        Map<Integer, ParameterContainer> parameters = new java.util.HashMap<>();
        int nextParameterIndex = 0;
        for (Element parameterElement : children(element, "Parameter")) {
            int index = intValue(attribute(parameterElement, "index", ""), nextParameterIndex);
            nextParameterIndex = Math.max(nextParameterIndex, index + 1);

            ParameterContainer parameter =
                    new ParameterContainer(
                            attribute(parameterElement, "name", ""),
                            readTypeContainer(parameterElement));
            parameters.put(index, parameter);
        }
        function.setParameters(parameters);
        XmlPresence.record(
                function,
                element,
                Map.ofEntries(
                        Map.entry("name", "name"),
                        Map.entry("address", "address"),
                        Map.entry("callingConvention", "callingConvention"),
                        Map.entry("headerFile", "headerFile"),
                        Map.entry("isOverride", "override"),
                        Map.entry("isStatic", "static"),
                        Map.entry("isVarargs", "varargs"),
                        Map.entry("isPureVirtual", "pureVirtual"),
                        Map.entry("implementationAddress", "implementationAddress"),
                        Map.entry("ReturnType", "returnType"),
                        Map.entry("Parameter", "parameters")));
        return function;
    }

    private static TypeContainer readTypeContainer(Element element) {
        TypeContainer type = new TypeContainer(namespaced(attribute(element, "type", "undefined")));
        type.setPrefix(attribute(element, "prefix", ""));
        type.setSuffix(attribute(element, "suffix", ""));
        type.setConst(booleanValue(attribute(element, "isConst", "false"), false));
        return type;
    }

    private static boolean hasFunctionData(Element element) {
        return element.getAttribute("address") != null
                || element.getAttribute("implementationAddress") != null
                || element.getAttribute("name") != null
                || element.getAttribute("callingConvention") != null
                || child(element, "ReturnType") != null
                || !children(element, "Parameter").isEmpty();
    }

    private static String attribute(Element element, String name, String defaultValue) {
        if (element == null) {
            return defaultValue;
        }
        String value = element.getAttributeValue(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    private static int intValue(String value, int defaultValue) {
        try {
            return Integer.decode(value);
        } catch (RuntimeException ignored) {
            return defaultValue;
        }
    }

    private static long longValue(String value, long defaultValue) {
        try {
            return Long.decode(value);
        } catch (RuntimeException ignored) {
            return defaultValue;
        }
    }

    private static Long nullableLongValue(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return Long.decode(value);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static boolean booleanValue(String value, boolean defaultValue) {
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        return defaultValue;
    }

    private static Util.NamespacedString namespaced(String value) {
        try {
            return Util.NamespacedString.parse(value);
        } catch (RuntimeException ignored) {
            return Util.NamespacedString.parse("undefined");
        }
    }

    private static Element child(Element parent, String name) {
        return parent == null ? null : parent.getChild(name);
    }

    private static List<Element> children(Element parent, String name) {
        if (parent == null) {
            return List.of();
        }
        return name == null ? parent.getChildren() : parent.getChildren(name);
    }

    public static FileContainer readContainerFromFile(Path path) throws IOException, JDOMException {
        SAXBuilder builder = new SAXBuilder(XMLReaders.NONVALIDATING);

        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        builder.setProperty(
                "http://www.oracle.com/xml/jaxp/properties/maxGeneralEntitySizeLimit", 0);
        builder.setProperty("http://www.oracle.com/xml/jaxp/properties/totalEntitySizeLimit", 0);

        Document document = builder.build(path.toFile());
        return deserialize(document.getRootElement());
    }
}
