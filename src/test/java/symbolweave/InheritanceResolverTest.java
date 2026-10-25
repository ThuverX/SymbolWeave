package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.TypeContainer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class InheritanceResolverTest {

    public static void main(String[] args) {
        inheritedPatchDeclarationIsOrderIndependent();
        patchCanOverrideAnalyzedPureVirtualState();
    }

    private static void patchCanOverrideAnalyzedPureVirtualState() {
        ClassContainer pcClass = cls(Util.NamespacedString.parse("Example"), 1, List.of());
        FunctionContainer analyzed = function(0x140001000L, "undefined", "void");
        analyzed.setImplementationAddress(0x140002000L);
        analyzed.setPureVirtual(true);
        pcClass.getVirtualFunctions().put(0, analyzed);

        ClassContainer patchClass = cls(Util.NamespacedString.parse("Example"), 0, List.of());
        FunctionContainer patchFunction = function(0, "Example::Run", "void");
        patchFunction.setPureVirtual(false);
        patchClass.getVirtualFunctions().put(0, patchFunction);

        FunctionContainer merged =
                ConfigurableMerger.merge(List.of(file(pcClass), file(patchClass)))
                        .getClasses()
                        .getFirst()
                        .getVirtualFunctions()
                        .get(0);
        assertEquals(false, merged.isPureVirtual());
        assertEquals(true, merged.hasPureVirtualValue());
        assertEquals(0x140002000L, merged.getImplementationAddress());
    }

    private static void inheritedPatchDeclarationIsOrderIndependent() {
        Util.NamespacedString parentName = Util.NamespacedString.parse("Example::Base");
        Util.NamespacedString childName = Util.NamespacedString.parse("Example::Derived");

        ClassContainer pcChild = cls(childName, 21, List.of(parentName));
        pcChild.getVirtualFunctions().put(19, function(0x1409A7328L, "undefined", "void"));
        ClassContainer pcParent = cls(parentName, 21, List.of());
        pcParent.getVirtualFunctions().put(19, function(0x1409A7170L, "undefined", "void"));

        FileContainer pc = file(pcChild, pcParent); // Child intentionally precedes its parent.
        FileContainer childPatch = file(cls(childName, 0, List.of()));
        ClassContainer patchedParent = cls(parentName, 0, List.of());
        patchedParent
                .getVirtualFunctions()
                .put(19, function(0, "Example::Base::OpenRecord", "bool"));
        FileContainer parentPatch = file(patchedParent); // Parent patch intentionally comes last.

        FileContainer merged = ConfigurableMerger.merge(List.of(pc, childPatch, parentPatch));
        FunctionContainer inherited =
                merged.getClasses().stream()
                        .filter(c -> c.getName().equals(childName))
                        .findFirst()
                        .orElseThrow()
                        .getVirtualFunctions()
                        .get(19);

        assertEquals("Example::Base::OpenRecord", inherited.getName().toString());
        assertEquals("bool", inherited.getReturnType().getName().toString());
        assertEquals(0x1409A7328L, inherited.getAddress());
    }

    private static ClassContainer cls(
            Util.NamespacedString name, int vtableCount, List<Util.NamespacedString> parents) {
        return new ClassContainer(
                name,
                0,
                vtableCount,
                new HashMap<>(),
                new ArrayList<>(),
                new ArrayList<>(parents),
                new ArrayList<>());
    }

    private static FileContainer file(ClassContainer... classes) {
        FileContainer file = new FileContainer("test");
        file.getClasses().addAll(List.of(classes));
        return file;
    }

    private static FunctionContainer function(long address, String name, String returnType) {
        return new FunctionContainer(
                address,
                Util.NamespacedString.parse(name),
                FunctionContainer.CallingConvention.THISCALL,
                new TypeContainer(Util.NamespacedString.parse(returnType)),
                new HashMap<>(),
                false,
                false);
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + " but got " + actual);
        }
    }
}
