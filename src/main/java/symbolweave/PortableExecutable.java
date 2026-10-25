package symbolweave;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Minimal, dependency-free PE32+ reader used by the signature generator. */
public final class PortableExecutable {
    public static final int IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private static final int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
    private static final int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
    private static final int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
    private static final int RT_VERSION = 16;

    public record Section(
            String name,
            long virtualAddress,
            long virtualSize,
            int rawOffset,
            int rawSize,
            int characteristics) {
        public boolean executable() {
            return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }

        public long mappedSize() {
            return Math.max(virtualSize, Integer.toUnsignedLong(rawSize));
        }
    }

    public record Version(String fileVersion, String productVersion) {}

    private final byte[] bytes;
    private final long imageBase;
    private final long timestamp;
    private final long sizeOfImage;
    private final int machine;
    private final List<Section> sections;
    private final long resourceRva;
    private final long resourceSize;
    private final long relocationRva;
    private final long relocationSize;
    private final DebugCodeView debugCodeView;
    private final String sha256;

    private PortableExecutable(
            byte[] bytes,
            long imageBase,
            long timestamp,
            long sizeOfImage,
            int machine,
            List<Section> sections,
            long resourceRva,
            long resourceSize,
            long relocationRva,
            long relocationSize,
            DebugCodeView debugCodeView,
            String sha256) {
        this.bytes = bytes;
        this.imageBase = imageBase;
        this.timestamp = timestamp;
        this.sizeOfImage = sizeOfImage;
        this.machine = machine;
        this.sections = List.copyOf(sections);
        this.resourceRva = resourceRva;
        this.resourceSize = resourceSize;
        this.relocationRva = relocationRva;
        this.relocationSize = relocationSize;
        this.debugCodeView = debugCodeView;
        this.sha256 = sha256;
    }

    public static PortableExecutable read(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        if (bytes.length < 0x40 || u16(bytes, 0) != 0x5A4D) {
            throw new IOException(path + " is not a DOS/PE executable");
        }
        int peOffset = checkedInt(u32(bytes, 0x3C), "PE header offset");
        require(bytes, peOffset, 24);
        if (u32(bytes, peOffset) != 0x00004550L) {
            throw new IOException(path + " has no PE signature");
        }

        int coff = peOffset + 4;
        int machine = u16(bytes, coff);
        int sectionCount = u16(bytes, coff + 2);
        long timestamp = u32(bytes, coff + 4);
        int optionalSize = u16(bytes, coff + 16);
        int optional = coff + 20;
        require(bytes, optional, optionalSize);
        if (u16(bytes, optional) != 0x20B) {
            throw new IOException(path + " is not a PE32+ executable");
        }
        if (machine != 0x8664) {
            throw new IOException(
                    path
                            + " is not an AMD64 executable (machine=0x"
                            + Integer.toHexString(machine)
                            + ")");
        }

        long imageBase = i64(bytes, optional + 24);
        long sizeOfImage = u32(bytes, optional + 56);
        int directoryCount =
                checkedInt(Math.min(u32(bytes, optional + 108), 16), "data directory count");
        long resourceRva = 0;
        long resourceSize = 0;
        long relocationRva = 0;
        long relocationSize = 0;
        long debugRva = 0;
        long debugSize = 0;
        if (directoryCount > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            int entry = optional + 112 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
            resourceRva = u32(bytes, entry);
            resourceSize = u32(bytes, entry + 4);
        }
        if (directoryCount > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            int entry = optional + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
            relocationRva = u32(bytes, entry);
            relocationSize = u32(bytes, entry + 4);
        }
        if (directoryCount > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            int entry = optional + 112 + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
            debugRva = u32(bytes, entry);
            debugSize = u32(bytes, entry + 4);
        }

        int sectionTable = optional + optionalSize;
        require(bytes, sectionTable, Math.multiplyExact(sectionCount, 40));
        List<Section> sections = new ArrayList<>();
        for (int index = 0; index < sectionCount; index++) {
            int offset = sectionTable + index * 40;
            int nameLength = 0;
            while (nameLength < 8 && bytes[offset + nameLength] != 0) nameLength++;
            String name =
                    new String(
                            bytes, offset, nameLength, java.nio.charset.StandardCharsets.US_ASCII);
            long virtualSize = u32(bytes, offset + 8);
            long virtualAddress = u32(bytes, offset + 12);
            int rawSize = checkedInt(u32(bytes, offset + 16), "section raw size");
            int rawOffset = checkedInt(u32(bytes, offset + 20), "section raw offset");
            int characteristics = (int) u32(bytes, offset + 36);
            if (rawSize > 0) require(bytes, rawOffset, rawSize);
            sections.add(
                    new Section(
                            name,
                            virtualAddress,
                            virtualSize,
                            rawOffset,
                            rawSize,
                            characteristics));
        }

        DebugCodeView debugCodeView = readDebugCodeView(bytes, sections, debugRva, debugSize);
        return new PortableExecutable(
                bytes,
                imageBase,
                timestamp,
                sizeOfImage,
                machine,
                sections,
                resourceRva,
                resourceSize,
                relocationRva,
                relocationSize,
                debugCodeView,
                sha256(bytes));
    }

    public record DebugCodeView(byte[] guid, long age, String path) {
        public DebugCodeView {
            guid = guid.clone();
        }
    }

    public DebugCodeView debugCodeView() {
        return debugCodeView;
    }

    private static DebugCodeView readDebugCodeView(
            byte[] bytes, List<Section> sections, long rva, long size) throws IOException {
        if (rva == 0 || size < 28) return null;
        int offset = rvaToOffset(sections, rva);
        if (offset < 0) return null;
        int end =
                Math.min(
                        bytes.length,
                        Math.addExact(offset, checkedInt(size, "debug directory size")));
        for (int cursor = offset; cursor + 28 <= end; cursor += 28) {
            if (u32(bytes, cursor + 12) != 2 || u32(bytes, cursor + 16) < 24) continue;
            int dataOffset = rvaToOffset(sections, u32(bytes, cursor + 20));
            if (dataOffset < 0
                    || dataOffset + 24 > bytes.length
                    || u32(bytes, dataOffset) != 0x53445352L) continue;
            byte[] guid = java.util.Arrays.copyOfRange(bytes, dataOffset + 4, dataOffset + 20);
            long age = u32(bytes, dataOffset + 20);
            int pathStart = dataOffset + 24;
            int pathEnd = pathStart;
            while (pathEnd < bytes.length && bytes[pathEnd] != 0) pathEnd++;
            String path =
                    new String(
                            bytes,
                            pathStart,
                            pathEnd - pathStart,
                            java.nio.charset.StandardCharsets.UTF_8);
            return new DebugCodeView(guid, age, path);
        }
        return null;
    }

    private static int rvaToOffset(List<Section> sections, long rva) {
        for (Section section : sections) {
            if (rva >= section.virtualAddress()
                    && rva < section.virtualAddress() + section.mappedSize()) {
                long delta = rva - section.virtualAddress();
                if (delta >= Integer.toUnsignedLong(section.rawSize())) return -1;
                long result = Integer.toUnsignedLong(section.rawOffset()) + delta;
                return result <= Integer.MAX_VALUE ? (int) result : -1;
            }
        }
        return rva <= Integer.MAX_VALUE ? (int) rva : -1;
    }

    public byte[] bytes() {
        return bytes;
    }

    public long imageBase() {
        return imageBase;
    }

    public long timestamp() {
        return timestamp;
    }

    public long sizeOfImage() {
        return sizeOfImage;
    }

    public int machine() {
        return machine;
    }

    public List<Section> sections() {
        return sections;
    }

    public String sha256() {
        return sha256;
    }

    public List<Section> executableSections() {
        return sections.stream()
                .filter(Section::executable)
                .filter(section -> section.rawSize() > 0)
                .toList();
    }

    public long vaToRva(long virtualAddress) {
        return virtualAddress - imageBase;
    }

    public int rvaToOffset(long rva) {
        for (Section section : sections) {
            if (rva >= section.virtualAddress()
                    && rva < section.virtualAddress() + section.mappedSize()) {
                long delta = rva - section.virtualAddress();
                if (delta >= Integer.toUnsignedLong(section.rawSize())) return -1;
                long result = Integer.toUnsignedLong(section.rawOffset()) + delta;
                return result <= Integer.MAX_VALUE && result < bytes.length ? (int) result : -1;
            }
        }
        return rva >= 0 && rva < bytes.length ? (int) rva : -1;
    }

    public int vaToOffset(long virtualAddress) {
        return rvaToOffset(vaToRva(virtualAddress));
    }

    public boolean isExecutableVa(long virtualAddress) {
        long rva = vaToRva(virtualAddress);
        return executableSections().stream()
                .anyMatch(
                        section ->
                                rva >= section.virtualAddress()
                                        && rva
                                                < section.virtualAddress()
                                                        + Integer.toUnsignedLong(
                                                                section.rawSize()));
    }

    public long readLongAtVa(long virtualAddress) throws IOException {
        int offset = vaToOffset(virtualAddress);
        if (offset < 0) throw new IOException("unmapped virtual address " + hex(virtualAddress));
        require(bytes, offset, 8);
        return i64(bytes, offset);
    }

    public boolean[] relocationMask() throws IOException {
        boolean[] mask = new boolean[bytes.length];
        if (relocationRva == 0 || relocationSize == 0) return mask;
        int cursor = rvaToOffset(relocationRva);
        int end =
                cursor < 0
                        ? -1
                        : Math.min(
                                bytes.length,
                                cursor + checkedInt(relocationSize, "relocation size"));
        if (cursor < 0) return mask;
        while (cursor + 8 <= end) {
            long pageRva = u32(bytes, cursor);
            int blockSize = checkedInt(u32(bytes, cursor + 4), "relocation block size");
            if (blockSize < 8 || cursor + blockSize > end) break;
            for (int entry = cursor + 8; entry + 2 <= cursor + blockSize; entry += 2) {
                int value = u16(bytes, entry);
                int type = value >>> 12;
                if (type != 10) continue; // IMAGE_REL_BASED_DIR64
                int fileOffset = rvaToOffset(pageRva + (value & 0x0FFF));
                if (fileOffset >= 0 && fileOffset + 8 <= mask.length) {
                    for (int index = 0; index < 8; index++) mask[fileOffset + index] = true;
                }
            }
            cursor += blockSize;
        }
        return mask;
    }

    public Version version() {
        try {
            byte[] blob = versionResource();
            if (blob == null) return new Version("", "");
            for (int index = 0; index + 24 <= blob.length; index++) {
                if (u32(blob, index) != 0xFEEF04BDL) continue;
                long fileMs = u32(blob, index + 8);
                long fileLs = u32(blob, index + 12);
                long productMs = u32(blob, index + 16);
                long productLs = u32(blob, index + 20);
                String fileVersion = resourceString(blob, "FileVersion");
                String productVersion = resourceString(blob, "ProductVersion");
                return new Version(
                        fileVersion.isBlank() ? versionString(fileMs, fileLs) : fileVersion,
                        productVersion.isBlank()
                                ? versionString(productMs, productLs)
                                : productVersion);
            }
        } catch (IOException ignored) {
            // Version information is descriptive; the SHA-256 remains authoritative.
        }
        return new Version("", "");
    }

    private byte[] versionResource() throws IOException {
        if (resourceRva == 0 || resourceSize == 0) return null;
        int root = rvaToOffset(resourceRva);
        if (root < 0) return null;
        int typeDirectory = resourceDirectoryChild(root, root, RT_VERSION);
        if (typeDirectory < 0) return null;
        int nameDirectory = firstResourceChild(root, typeDirectory);
        if (nameDirectory < 0) return null;
        int dataEntry = firstResourceChild(root, nameDirectory);
        if (dataEntry < 0) return null;
        require(bytes, dataEntry, 16);
        int dataOffset = rvaToOffset(u32(bytes, dataEntry));
        int dataSize = checkedInt(u32(bytes, dataEntry + 4), "version resource size");
        if (dataOffset < 0) return null;
        require(bytes, dataOffset, dataSize);
        return java.util.Arrays.copyOfRange(bytes, dataOffset, dataOffset + dataSize);
    }

    private int resourceDirectoryChild(int root, int directory, int wantedId) throws IOException {
        require(bytes, directory, 16);
        int count = u16(bytes, directory + 12) + u16(bytes, directory + 14);
        require(bytes, directory + 16, Math.multiplyExact(count, 8));
        for (int index = 0; index < count; index++) {
            int entry = directory + 16 + index * 8;
            long name = u32(bytes, entry);
            if ((name & 0x80000000L) == 0 && (name & 0xFFFF) == wantedId) {
                return resourceTarget(root, entry);
            }
        }
        return -1;
    }

    private int firstResourceChild(int root, int directory) throws IOException {
        require(bytes, directory, 24);
        int count = u16(bytes, directory + 12) + u16(bytes, directory + 14);
        if (count == 0) return -1;
        return resourceTarget(root, directory + 16);
    }

    private int resourceTarget(int root, int entry) throws IOException {
        long child = u32(bytes, entry + 4);
        int result = Math.addExact(root, checkedInt(child & 0x7FFFFFFFL, "resource child offset"));
        require(bytes, result, (child & 0x80000000L) != 0 ? 16 : 16);
        return result;
    }

    private static String versionString(long ms, long ls) {
        return ((ms >>> 16) & 0xFFFF)
                + "."
                + (ms & 0xFFFF)
                + "."
                + ((ls >>> 16) & 0xFFFF)
                + "."
                + (ls & 0xFFFF);
    }

    private static String resourceString(byte[] blob, String key) {
        byte[] needle = (key + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        outer:
        for (int offset = 0; offset <= blob.length - needle.length; offset++) {
            for (int index = 0; index < needle.length; index++) {
                if (blob[offset + index] != needle[index]) continue outer;
            }
            int value = (offset + needle.length + 3) & ~3;
            StringBuilder result = new StringBuilder();
            while (value + 1 < blob.length) {
                int character =
                        Byte.toUnsignedInt(blob[value]) | Byte.toUnsignedInt(blob[value + 1]) << 8;
                if (character == 0) break;
                result.append((char) character);
                value += 2;
            }
            return result.toString().trim().replaceAll("\\s*,\\s*", ".");
        }
        return "";
    }

    private static String sha256(byte[] bytes) throws IOException {
        try {
            return HexFormat.of()
                    .withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 is unavailable", exception);
        }
    }

    static int u16(byte[] bytes, int offset) throws IOException {
        require(bytes, offset, 2);
        return Short.toUnsignedInt(
                ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.LITTLE_ENDIAN).getShort());
    }

    static long u32(byte[] bytes, int offset) throws IOException {
        require(bytes, offset, 4);
        return Integer.toUnsignedLong(
                ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    static long i64(byte[] bytes, int offset) throws IOException {
        require(bytes, offset, 8);
        return ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    static void require(byte[] bytes, int offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset > bytes.length - length) {
            throw new IOException(
                    "truncated PE data at file offset " + offset + " (length " + length + ")");
        }
    }

    private static int checkedInt(long value, String description) throws IOException {
        if (value < 0 || value > Integer.MAX_VALUE)
            throw new IOException(description + " is too large: " + value);
        return (int) value;
    }

    private static String hex(long value) {
        return String.format("0x%X", value);
    }
}
