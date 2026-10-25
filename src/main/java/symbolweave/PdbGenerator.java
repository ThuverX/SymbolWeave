package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Writes a compact native PDB containing CodeView public symbols for the merged SDK. */
public final class PdbGenerator {
    private static final int PAGE_SIZE = 0x400;
    private static final byte[] MAGIC =
            "Microsoft C/C++ MSF 7.00\r\n\u001ADS\0\0\0".getBytes(StandardCharsets.ISO_8859_1);
    private static final int S_PUB32 = 0x110E;
    private static final int DEBUG_S_SYMBOLS = 0xF1;

    private record Symbol(long address, String name) {}

    public record Result(Path path, int symbolCount, int skippedCount) {}

    private PdbGenerator() {}

    public static Result generate(FileContainer container, Path executable, Path output)
            throws IOException {
        return generate(container, executable, output, null);
    }

    public static Result generate(
            FileContainer container, Path executable, Path output, String configuredModule)
            throws IOException {
        String moduleName =
                configuredModule == null
                        ? executable.getFileName().toString().replaceAll("(?i)\\.exe$", "")
                        : configuredModule;
        if (moduleName.indexOf(0) >= 0)
            throw new IllegalArgumentException("PDB module name cannot contain a NUL");
        PortableExecutable pe = PortableExecutable.read(executable);
        PortableExecutable.DebugCodeView cv = pe.debugCodeView();
        if (cv == null)
            throw new IOException(executable.getFileName() + " has no RSDS CodeView record");

        Map<Long, Symbol> byAddress = new LinkedHashMap<>();
        int skipped = 0;
        for (FunctionContainer function : functions(container)) {
            long address =
                    function.getImplementationAddress() != 0
                            ? function.getImplementationAddress()
                            : function.getAddress();
            String name = function.getName() == null ? "" : function.getName().toString();
            if (address == 0 || name.isBlank() || !pe.isExecutableVa(address)) {
                skipped++;
                continue;
            }
            byAddress.putIfAbsent(address, new Symbol(address, name));
        }
        List<Symbol> symbols =
                byAddress.values().stream()
                        .sorted(
                                Comparator.comparingLong(Symbol::address)
                                        .thenComparing(Symbol::name))
                        .toList();
        Files.createDirectories(output);
        Path path =
                output.resolve(
                        executable.getFileName().toString().replaceAll("(?i)\\.exe$", "") + ".pdb");
        Files.write(path, build(pe, cv, symbols, moduleName));
        return new Result(path, symbols.size(), skipped);
    }

    private static List<FunctionContainer> functions(FileContainer container) {
        List<FunctionContainer> result = new ArrayList<>(container.getLooseFunctions());
        for (ClassContainer cls : container.getClasses()) {
            result.addAll(cls.getFunctions());
            result.addAll(
                    cls.getVirtualFunctions().values().stream().filter(f -> f != null).toList());
        }
        return result;
    }

    private static byte[] build(
            PortableExecutable pe,
            PortableExecutable.DebugCodeView cv,
            List<Symbol> symbols,
            String moduleName)
            throws IOException {
        List<byte[]> streams = new ArrayList<>();
        streams.add(new byte[0]);
        streams.add(pdbInfo(cv));
        streams.add(new byte[56]);
        streams.add(dbi(symbols, cv.age(), moduleName));
        streams.add(new byte[56]);
        streams.add(new byte[16]);
        streams.add(module(pe, symbols));
        return msf(streams);
    }

    private static byte[] pdbInfo(PortableExecutable.DebugCodeView cv) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        put32(out, 20000404);
        put32(out, 0);
        put32(out, cv.age());
        out.writeBytes(cv.guid());
        return out.toByteArray();
    }

    private static byte[] module(PortableExecutable pe, List<Symbol> symbols) {
        byte[] records = symbolRecords(pe, symbols);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        put32(out, DEBUG_S_SYMBOLS);
        put32(out, records.length);
        out.writeBytes(records);
        return out.toByteArray();
    }

    private static byte[] symbolRecords(PortableExecutable pe, List<Symbol> symbols) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Symbol symbol : symbols) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            put32(body, 0); // flags
            put32(body, symbol.address() - pe.imageBase()); // RVA
            put16(body, 1); // .text section
            body.writeBytes(symbol.name().getBytes(StandardCharsets.UTF_8));
            body.write(0);
            put16(out, body.size() + 2);
            put16(out, S_PUB32);
            out.writeBytes(body.toByteArray());
        }
        return out.toByteArray();
    }

    private static byte[] dbi(List<Symbol> symbols, long age, String moduleName) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        put32(out, 0xFFFFFFFFL);
        put32(out, 19990903);
        put32(out, age);
        put16(out, 0xFFFF);
        put16(out, 0);
        put16(out, 0xFFFF);
        put16(out, 0xFFFF);
        put16(out, 1);
        put16(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put16(out, 0);
        put16(out, 0x8664);
        put32(out, 0); // reserved
        // One module: no section contribution, module stream 6, C13 symbol bytes.
        put32(out, 0);
        out.writeBytes(new byte[16]);
        put16(out, 0);
        put16(out, 6);
        put32(out, moduleSymbolSize(symbols));
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        put32(out, 0);
        out.writeBytes((moduleName + "\0" + moduleName + "\0").getBytes(StandardCharsets.UTF_8));
        return out.toByteArray();
    }

    private static int moduleSymbolSize(List<Symbol> symbols) {
        int size = 8;
        for (Symbol symbol : symbols)
            size += 2 + 2 + 12 + symbol.name().getBytes(StandardCharsets.UTF_8).length + 1;
        return size;
    }

    private static byte[] msf(List<byte[]> streams) {
        int page = 1;
        List<List<Integer>> pages = new ArrayList<>();
        for (byte[] stream : streams) {
            int count = Math.max(1, (stream.length + PAGE_SIZE - 1) / PAGE_SIZE);
            List<Integer> streamPages = new ArrayList<>();
            for (int i = 0; i < count; i++) streamPages.add(page++);
            pages.add(streamPages);
        }
        int directorySize = 4 + streams.size() * 4;
        for (List<Integer> streamPages : pages) directorySize += streamPages.size() * 4;
        int directoryPages = Math.max(1, (directorySize + PAGE_SIZE - 1) / PAGE_SIZE);
        int directoryRoot = page;
        page += directoryPages;
        byte[] result = new byte[page * PAGE_SIZE];
        System.arraycopy(MAGIC, 0, result, 0, MAGIC.length);
        put32(result, 32, PAGE_SIZE);
        put32(result, 36, 1);
        put32(result, 40, page);
        put32(result, 44, directorySize);
        put32(result, 48, 0);
        put32(result, 52, directoryRoot);

        ByteArrayOutputStream directory = new ByteArrayOutputStream(directoryPages * PAGE_SIZE);
        put32(directory, streams.size());
        for (byte[] stream : streams) put32(directory, stream.length);
        for (List<Integer> streamPages : pages)
            for (int streamPage : streamPages) put32(directory, streamPage);
        byte[] directoryBytes = directory.toByteArray();
        System.arraycopy(
                directoryBytes, 0, result, directoryRoot * PAGE_SIZE, directoryBytes.length);
        for (int i = 0; i < streams.size(); i++) {
            byte[] stream = streams.get(i);
            List<Integer> streamPages = pages.get(i);
            for (int j = 0; j < stream.length; j++)
                result[streamPages.get(j / PAGE_SIZE) * PAGE_SIZE + j % PAGE_SIZE] = stream[j];
        }
        return result;
    }

    private static void put16(ByteArrayOutputStream out, int value) {
        out.write(value);
        out.write(value >>> 8);
    }

    private static void put32(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 4; i++) out.write((int) (value >>> (8 * i)));
    }

    private static void put32(byte[] out, int offset, long value) {
        for (int i = 0; i < 4; i++) out[offset + i] = (byte) (value >>> (8 * i));
    }
}
