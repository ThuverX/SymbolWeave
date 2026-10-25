package symbolweave;

import java.util.ArrayList;
import java.util.List;

public class Util {
    public static class NamespacedString {

        public static NamespacedString ROOT = new NamespacedString("");

        private List<String> namespaces = new ArrayList<>();
        private String name;

        public NamespacedString(String... parts) {
            List<String> partsList = List.of(parts);

            if (parts.length == 1) {
                this.name = parts[0];
            } else {
                this.namespaces = partsList.subList(0, partsList.size() - 1);
                this.name = partsList.get(partsList.size() - 1);
            }
        }

        @Override
        public String toString() {
            StringBuilder br = new StringBuilder();
            for (String namespace : namespaces) {
                br.append(namespace).append("::");
            }
            br.append(name);
            return br.toString();
        }

        public List<String> getNamespaces() {
            return namespaces;
        }

        public List<String> getParts() {
            var list = new ArrayList<>(namespaces);
            list.add(name);
            return list;
        }

        public String getName() {
            return name;
        }

        public NamespacedString append(String name) {
            NamespacedString ns = new NamespacedString();
            ns.namespaces = List.copyOf(this.namespaces);
            ns.namespaces.add(this.name);
            ns.name = name;
            return ns;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            return o.toString().equals(this.toString());
        }

        @Override
        public int hashCode() {
            return toString().hashCode();
        }

        public static NamespacedString parse(String format) {
            if (format == null || format.isEmpty()) return new NamespacedString("");
            List<String> namespaces = new ArrayList<>();
            int depth = 0;

            int i = 0;
            byte[] chars = format.getBytes();

            String active = "";

            while (i < chars.length) {
                if (chars[i] == '<') {
                    depth++;
                    active += (char) chars[i];
                } else if (chars[i] == '>') {
                    depth--;
                    active += (char) chars[i];
                } else if (i < chars.length - 1 && chars[i] == ':' && chars[i + 1] == ':') {
                    if (depth == 0) {
                        namespaces.add(active);
                        active = "";
                        i++;
                    } else {
                        active += (char) chars[i];
                    }
                } else {
                    active += (char) chars[i];
                }
                i++;
            }

            if (!active.isEmpty()) {
                namespaces.add(active);
            }

            return new NamespacedString(namespaces.toArray(new String[0]));
        }

        public boolean isTopLevel() {
            return this.namespaces.isEmpty();
        }

        public NamespacedString parent() {
            return new NamespacedString(namespaces.toArray(new String[0]));
        }
    }
}
