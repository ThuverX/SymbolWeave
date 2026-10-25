package symbolweave;

import org.jdom2.Element;

import java.util.*;

/** Omission and explicit clearing are retained separately from model default values. */
final class XmlPresence {
    private record Fields(Set<String> present, Set<String> cleared) {}

    private static final Map<Object, Fields> FIELDS =
            Collections.synchronizedMap(new WeakHashMap<>());

    static void record(Object model, Element element, Map<String, String> names) {
        Set<String> fields = new HashSet<>();
        for (var entry : names.entrySet())
            if (element.getAttribute(entry.getKey()) != null
                    || element.getChild(entry.getKey()) != null) fields.add(entry.getValue());
        if (model instanceof symbolweave.containers.ClassContainer
                && element.getChild("Functions") != null) fields.add("virtualFunctions");
        Set<String> cleared = new HashSet<>();
        String clear = element.getAttributeValue("clear");
        if (clear != null)
            for (String name : clear.split(",")) {
                fields.add(name.trim());
                cleared.add(name.trim());
            }
        FIELDS.put(model, new Fields(fields, cleared));
    }

    static boolean omitted(Object model, String field) {
        var value = FIELDS.get(model);
        return value != null && !value.present().contains(field);
    }

    static boolean cleared(Object model, String field) {
        var value = FIELDS.get(model);
        return value != null && value.cleared().contains(field);
    }

    static void supplied(Object model, String field) {
        Fields value = FIELDS.get(model);
        if (value != null) value.present().add(field);
    }

    static void copy(Object source, Object target) {
        var value = FIELDS.get(source);
        if (value != null) FIELDS.put(target, value);
    }
}
