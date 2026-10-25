package symbolweave;

import com.google.gson.*;

import java.util.*;

public final class Options {
    private Options() {}

    public static String string(JsonObject o, String k, String fallback) {
        return o.has(k) ? o.get(k).getAsString() : fallback;
    }

    public static String required(JsonObject o, String k) {
        if (!o.has(k) || o.get(k).getAsString().isBlank())
            throw new IllegalArgumentException("Missing plugin option: " + k);
        return o.get(k).getAsString();
    }

    public static int integer(JsonObject o, String k, int fallback) {
        return o.has(k) ? o.get(k).getAsInt() : fallback;
    }

    public static boolean bool(JsonObject o, String k, boolean fallback) {
        return o.has(k) ? o.get(k).getAsBoolean() : fallback;
    }

    public static void check(JsonObject o, String plugin, Set<String> allowed) {
        for (String key : o.keySet())
            if (!allowed.contains(key))
                throw new IllegalArgumentException("Unknown " + plugin + " option: " + key);
    }
}
