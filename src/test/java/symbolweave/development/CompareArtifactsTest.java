package symbolweave.development;

import java.nio.file.*;

public final class CompareArtifactsTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("symbolweave-compare-");
        Path expected = root.resolve("expected.xml"), actual = root.resolve("actual.xml");
        Files.writeString(
                expected,
                "<Data><Functions><Function name='A'/><Function name='B'"
                        + " type='FuncDef1'/></Functions></Data>");
        Files.writeString(
                actual,
                "<Data><Functions><Function type='FuncDef7' name='B'/><Function"
                        + " name='A'/></Functions></Data>");
        String[] normalized = {expected.toString(), actual.toString(), "--normalize-anonymous"};
        if (CompareArtifacts.compare(normalized) != 0)
            throw new AssertionError("Equivalent XML differs");
        if (CompareArtifacts.compare(new String[] {expected.toString(), actual.toString()}) != 1)
            throw new AssertionError("Different type IDs ignored");
        Path headersA = Files.createDirectory(root.resolve("a")),
                headersB = Files.createDirectory(root.resolve("b"));
        Files.writeString(headersA.resolve("Header.h"), "struct Type;\r\n");
        Files.writeString(headersB.resolve("Header.h"), "struct Type;\n");
        String[] withHeaders = {
            expected.toString(),
            actual.toString(),
            "--normalize-anonymous",
            "--expected-headers",
            headersA.toString(),
            "--actual-headers",
            headersB.toString()
        };
        if (CompareArtifacts.compare(withHeaders) != 0)
            throw new AssertionError("Line endings changed comparison");
        Files.writeString(headersB.resolve("Header.h"), "struct Different;\n");
        if (CompareArtifacts.compare(withHeaders) != 1)
            throw new AssertionError("Header difference ignored");
        System.out.println("Java XML/header comparison passed");
    }
}
