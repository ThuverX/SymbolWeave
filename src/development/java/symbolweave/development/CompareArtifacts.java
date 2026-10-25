package symbolweave.development;

import org.w3c.dom.*;

import java.nio.file.*;
import java.util.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

/** Semantic XML and generated-header comparison, independent of shell or Python runtimes. */
public final class CompareArtifacts {
    private CompareArtifacts() {}

    public static void main(String[] args) throws Exception {
        int status = compare(args);
        if (status != 0) System.exit(status);
    }

    public static int compare(String[] args) throws Exception {
        if (args.length < 2)
            throw new IllegalArgumentException(
                    "Usage: java SymbolWeave.java compare expected.xml actual.xml"
                        + " [--expected-headers dir --actual-headers dir] [--normalize-anonymous]");
        Path expected = Path.of(args[0]),
                actual = Path.of(args[1]),
                expectedHeaders = null,
                actualHeaders = null;
        boolean normalize = false;
        for (int i = 2; i < args.length; i++)
            switch (args[i]) {
                case "--normalize-anonymous" -> normalize = true;
                case "--expected-headers" -> expectedHeaders = Path.of(value(args, ++i));
                case "--actual-headers" -> actualHeaders = Path.of(value(args, ++i));
                default ->
                        throw new IllegalArgumentException("Unknown comparison option: " + args[i]);
            }
        if ((expectedHeaders == null) != (actualHeaders == null))
            throw new IllegalArgumentException(
                    "Supply both --expected-headers and --actual-headers");
        Element expectedXml = readXml(expected), actualXml = readXml(actual);
        boolean passed = canonical(expectedXml, normalize).equals(canonical(actualXml, normalize));
        System.out.println("XML semantic parity: " + (passed ? "PASS" : "FAIL"));
        System.out.println(
                "Classes: expected="
                        + expectedXml.getElementsByTagName("Class").getLength()
                        + " actual="
                        + actualXml.getElementsByTagName("Class").getLength());
        System.out.println(
                "Virtual entries: expected="
                        + expectedXml.getElementsByTagName("VirtualFunction").getLength()
                        + " actual="
                        + actualXml.getElementsByTagName("VirtualFunction").getLength());
        if (expectedHeaders != null) {
            if (!Files.isDirectory(expectedHeaders) || !Files.isDirectory(actualHeaders))
                throw new IllegalArgumentException("Header roots must be existing directories");
            List<Path> files;
            try (var paths = Files.walk(expectedHeaders)) {
                files =
                        paths.filter(Files::isRegularFile)
                                .filter(CompareArtifacts::isHeader)
                                .sorted()
                                .toList();
            }
            List<Path> differences = new ArrayList<>();
            for (Path file : files) {
                Path relative = expectedHeaders.relativize(file),
                        target = actualHeaders.resolve(relative);
                if (!Files.isRegularFile(target)
                        || !normalize(Files.readString(file), normalize)
                                .equals(normalize(Files.readString(target), normalize)))
                    differences.add(relative);
            }
            System.out.println(
                    "Headers compared: " + files.size() + "; differences: " + differences.size());
            differences.stream().limit(30).forEach(path -> System.out.println("  " + path));
            passed &= differences.isEmpty();
        }
        if (normalize)
            System.out.println(
                    "Anonymous FuncDef numeric IDs were normalized; all other metadata was"
                            + " compared.");
        return passed ? 0 : 1;
    }

    private static String value(String[] args, int index) {
        if (index == args.length) throw new IllegalArgumentException("Missing header directory");
        return args[index];
    }

    private static boolean isHeader(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".h")
                || name.endsWith(".hh")
                || name.endsWith(".hpp")
                || name.endsWith(".hxx");
    }

    private static String normalize(String value, boolean anonymous) {
        String text = value.replace("\r\n", "\n").replace('\r', '\n');
        return anonymous ? text.replaceAll("FuncDef\\d+", "FuncDef#") : text;
    }

    private static Element readXml(Path path) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(path.toFile()).getDocumentElement();
    }

    private static void token(StringBuilder text, String value) {
        text.append(value.length()).append(':').append(value);
    }

    private static String canonical(Element element, boolean normalize) {
        StringBuilder result = new StringBuilder();
        token(result, element.getTagName());
        Map<String, String> attributes = new TreeMap<>();
        for (int i = 0; i < element.getAttributes().getLength(); i++) {
            var attr = element.getAttributes().item(i);
            attributes.put(attr.getNodeName(), normalize(attr.getNodeValue(), normalize));
        }
        result.append('[');
        attributes.forEach(
                (key, value) -> {
                    token(result, key);
                    token(result, value);
                });
        result.append(']');
        List<String> children = new ArrayList<>();
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element child) children.add(canonical(child, normalize));
        Collections.sort(children);
        result.append('[');
        children.forEach(child -> token(result, child));
        return result.append(']').toString();
    }
}
