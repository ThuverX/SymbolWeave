package symbolweave;

import symbolweave.containers.FileContainer;

import java.nio.file.Files;
import java.nio.file.Path;

public final class SignatureDatabaseGeneratorTest {
    public static void main(String[] args) throws Exception {
        decoderWildcardsRelativeAddresses();
        if (args.length == 3)
            realExecutableProducesVerifiedDatabase(
                    Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
    }

    private static void decoderWildcardsRelativeAddresses() {
        byte[] call = bytes("E8 78 56 34 12");
        X64InstructionDecoder.Instruction callInstruction =
                X64InstructionDecoder.decode(call, 0, call.length);
        assertEquals(5, callInstruction.length());
        assertField(callInstruction, 1, 4);

        byte[] lea = bytes("48 8D 0D 78 56 34 12");
        X64InstructionDecoder.Instruction leaInstruction =
                X64InstructionDecoder.decode(lea, 0, lea.length);
        assertEquals(7, leaInstruction.length());
        assertField(leaInstruction, 3, 4);

        byte[] prologue = bytes("48 89 5C 24 08");
        X64InstructionDecoder.Instruction prologueInstruction =
                X64InstructionDecoder.decode(prologue, 0, prologue.length);
        assertEquals(5, prologueInstruction.length());
        assertEquals(0, prologueInstruction.wildcardFields().size());
    }

    private static void realExecutableProducesVerifiedDatabase(
            Path executable, Path xml, Path output) throws Exception {
        PortableExecutable pe = PortableExecutable.read(executable);
        assertEquals("AMD64", pe.machine() == 0x8664 ? "AMD64" : "other");
        assertEquals(64, pe.sha256().length());

        FileContainer sdk = DataXMLSerializer.readContainerFromFile(xml);
        SignatureDatabaseGenerator.Result result =
                SignatureDatabaseGenerator.generate(sdk, executable, output);
        assertEquals(true, Files.isRegularFile(result.path()));
        assertEquals(true, result.patternCount() > 0);
        assertEquals(true, result.entityCount() >= result.patternCount());
        String database = Files.readString(result.path());
        assertContains(database, "\"sha256\": \"" + pe.sha256() + "\"");
        assertContains(database, "\"matches\": 1");
    }

    private static byte[] bytes(String text) {
        String[] parts = text.split(" ");
        byte[] result = new byte[parts.length];
        for (int index = 0; index < parts.length; index++)
            result[index] = (byte) Integer.parseInt(parts[index], 16);
        return result;
    }

    private static void assertField(
            X64InstructionDecoder.Instruction instruction, int offset, int length) {
        if (instruction.wildcardFields().stream()
                .noneMatch(field -> field.offset() == offset && field.length() == length)) {
            throw new AssertionError("missing wildcard field at " + offset + " length " + length);
        }
    }

    private static void assertContains(String actual, String expected) {
        if (!actual.contains(expected)) throw new AssertionError("missing: " + expected);
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual))
            throw new AssertionError("expected " + expected + ", got " + actual);
    }
}
