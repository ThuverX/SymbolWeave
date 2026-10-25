package symbolweave.development;

import com.google.gson.*;

import symbolweave.ProjectConfig;

import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

public final class ConfigSchema {
    static JsonObject schema(Type type) {
        JsonObject value = new JsonObject();
        if (type instanceof ParameterizedType p) {
            if (p.getRawType() == List.class) {
                value.addProperty("type", "array");
                value.add("items", schema(p.getActualTypeArguments()[0]));
            } else {
                value.addProperty("type", "object");
                value.add("additionalProperties", schema(p.getActualTypeArguments()[1]));
            }
            return value;
        }
        Class<?> c = (Class<?>) type;
        if (c == JsonObject.class || c == JsonElement.class) return value;
        if (c == String.class) value.addProperty("type", "string");
        else if (c == int.class) value.addProperty("type", "integer");
        else if (c == double.class) value.addProperty("type", "number");
        else if ((c == boolean.class || c == Boolean.class)) value.addProperty("type", "boolean");
        else {
            value.addProperty("type", "object");
            value.addProperty("additionalProperties", false);
            JsonObject properties = new JsonObject();
            for (Field field : c.getFields())
                if (!Modifier.isStatic(field.getModifiers()))
                    properties.add(field.getName(), schema(field.getGenericType()));
            value.add("properties", properties);
            JsonArray required = new JsonArray();
            if (c == ProjectConfig.class) {
                required.add("version");
                required.add("inputs");
                properties.add("$schema", schema(String.class));
                properties.getAsJsonObject("version").addProperty("const", 1);
            }
            if (c == ProjectConfig.Input.class) {
                required.add("id");
                required.add("xml");
            }
            if (c == ProjectConfig.Match.class) {
                required.add("source");
                required.add("target");
                required.add("plugin");
            }
            if (c == ProjectConfig.Script.class) required.add("name");
            if (!required.isEmpty()) value.add("required", required);
        }
        return value;
    }

    public static void main(String[] args) throws Exception {
        JsonObject root = schema(ProjectConfig.class);
        root.addProperty("$schema", "https://json-schema.org/draft/2020-12/schema");
        root.addProperty("title", "SymbolWeave project configuration");
        root.addProperty(
                "description",
                "Analysis, matching, merging, and SDK generation settings for SymbolWeave.");
        var buffer = new java.io.StringWriter();
        var writer = new com.google.gson.stream.JsonWriter(buffer);
        writer.setIndent("    ");
        ProjectConfig.JSON.toJson(root, writer);
        String generated = buffer + "\n";
        Path path = Path.of(args[0]);
        if (args.length > 1 && args[1].equals("--check")) {
            if (!Files.readString(path).equals(generated))
                throw new IllegalStateException(
                        "Configuration schema is stale; run java SymbolWeave.java schema");
            System.out.println("Configuration schema is current");
        } else {
            Files.writeString(path, generated);
            System.out.println("Wrote " + path);
        }
    }
}
