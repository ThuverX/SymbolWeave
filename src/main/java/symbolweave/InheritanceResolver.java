package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class InheritanceResolver {

    private InheritanceResolver() {}

    static void resolve(
            FileContainer container,
            Map<Util.NamespacedString, Set<Integer>> patched,
            ProjectConfig.Merge settings) {
        if (settings.backfillDeclarations) backfillFunctionDeclarations(container.getClasses());
        if (settings.synchronizeSecondary)
            synchronizeSecondaryVtableDeclarations(container.getClasses());
        if (settings.synchronizePrimary)
            synchronizePrimaryVtableDeclarations(container.getClasses(), patched);
    }

    private static int logicalSlotCount(ClassContainer cls) {
        return Math.max(
                cls.getVtableCount(),
                cls.getVirtualFunctions().keySet().stream()
                        .mapToInt(index -> index + 1)
                        .max()
                        .orElse(0));
    }

    private static void backfillFunctionDeclarations(List<ClassContainer> classes) {
        Map<ClassContainer, ClassContainer> directParents = new HashMap<>();
        for (ClassContainer child : classes) {
            directParents.put(child, findDirectParent(child, classes));
        }

        boolean changed;
        do {
            changed = false;

            // A derived vtable is the best available declaration source for gaps in its direct
            // parent.
            for (ClassContainer child : classes) {
                ClassContainer parent = directParents.get(child);
                if (parent == null) continue;

                for (int slot = 0;
                        slot < Math.min(parent.getVtableCount(), child.getVtableCount());
                        slot++) {
                    FunctionContainer parentFunction = parent.getVirtualFunctions().get(slot);
                    FunctionContainer childFunction = child.getVirtualFunctions().get(slot);
                    if (hasDeclaration(parentFunction) || !hasDeclaration(childFunction)) continue;

                    long address = parentFunction == null ? 0 : parentFunction.getAddress();
                    Util.NamespacedString functionName =
                            Util.NamespacedString.parse(
                                    parent.getName() + "::" + childFunction.getName().getName());
                    FunctionContainer inferred =
                            copyDeclaration(childFunction, address, functionName);
                    if (parentFunction != null) copyAnalysis(parentFunction, inferred);
                    parent.getVirtualFunctions().put(slot, inferred);
                    changed = true;
                }
            }
        } while (changed);
    }

    /**
     * Propagates declarations supplied by patches through primary inheritance. The platform data
     * contains a separately named function for every concrete vtable entry, even when the generated
     * C++ class inherits that slot without declaring it. Once all patches have been applied, an
     * unpatched child slot must therefore use the nearest patched ancestor's declaration while
     * retaining the address from the child's own vtable.
     */
    private static void synchronizePrimaryVtableDeclarations(
            List<ClassContainer> classes,
            Map<Util.NamespacedString, Set<Integer>> patchedVtableSlots) {
        Map<ClassContainer, Set<Integer>> authoritativeSlots = new HashMap<>();
        Set<ClassContainer> visiting = new HashSet<>();

        for (ClassContainer child : classes) {
            synchronizePrimaryVtableDeclarations(
                    child, classes, patchedVtableSlots, authoritativeSlots, visiting);
        }
    }

    private static Set<Integer> synchronizePrimaryVtableDeclarations(
            ClassContainer child,
            List<ClassContainer> classes,
            Map<Util.NamespacedString, Set<Integer>> patchedVtableSlots,
            Map<ClassContainer, Set<Integer>> authoritativeSlots,
            Set<ClassContainer> visiting) {
        Set<Integer> cachedSlots = authoritativeSlots.get(child);
        if (cachedSlots != null) return cachedSlots;

        Set<Integer> childSlots =
                new HashSet<>(patchedVtableSlots.getOrDefault(child.getName(), Set.of()));
        if (!visiting.add(child)) return childSlots;

        ClassContainer parent = findDirectParent(child, classes);
        if (parent != null) {
            Set<Integer> parentSlots =
                    synchronizePrimaryVtableDeclarations(
                            parent, classes, patchedVtableSlots, authoritativeSlots, visiting);
            int sharedSlotCount = Math.min(parent.getVtableCount(), child.getVtableCount());

            for (int slot = 0; slot < sharedSlotCount; slot++) {
                if (childSlots.contains(slot)
                        || !parentSlots.contains(slot)
                        || !child.getVirtualFunctions().containsKey(slot)) continue;

                FunctionContainer parentFunction = parent.getVirtualFunctions().get(slot);
                if (!hasDeclaration(parentFunction)) continue;

                FunctionContainer childFunction = child.getVirtualFunctions().get(slot);
                long address = childFunction == null ? 0 : childFunction.getAddress();
                FunctionContainer inherited = copyInheritedDeclaration(parentFunction, address);
                if (childFunction != null) copyAnalysis(childFunction, inherited);
                child.getVirtualFunctions().put(slot, inherited);
                childSlots.add(slot);
            }
        }

        visiting.remove(child);
        authoritativeSlots.put(child, childSlots);
        return childSlots;
    }

    private static void synchronizeSecondaryVtableDeclarations(List<ClassContainer> classes) {
        for (ClassContainer child : classes) {
            List<ClassContainer> directParents = findDirectParents(child, classes);
            if (directParents.isEmpty()) continue;

            int childSlot = child.getVtableCount();
            ClassContainer primaryParent = directParents.getFirst();
            childSlot =
                    synchronizeParentSlots(
                            child, primaryParent, primaryParent.getVtableCount(), childSlot);

            for (int parentIndex = 1; parentIndex < directParents.size(); parentIndex++) {
                childSlot =
                        synchronizeParentSlots(child, directParents.get(parentIndex), 0, childSlot);
            }
        }
    }

    private static int synchronizeParentSlots(
            ClassContainer child, ClassContainer parent, int parentStartSlot, int childStartSlot) {
        int parentSlotCount = logicalSlotCount(parent);
        int childSlot = childStartSlot;

        for (int parentSlot = parentStartSlot;
                parentSlot < parentSlotCount;
                parentSlot++, childSlot++) {
            if (!child.getVirtualFunctions().containsKey(childSlot)) break;

            FunctionContainer childFunction = child.getVirtualFunctions().get(childSlot);
            FunctionContainer parentFunction = parent.getVirtualFunctions().get(parentSlot);
            if (!hasDeclaration(parentFunction)) continue;

            long address = childFunction == null ? 0 : childFunction.getAddress();
            // A slot can only use C++ `override` when the corresponding declaration is
            // actually emitted by the generated parent header. Logical tail slots that
            // were recovered from another platform are useful vtable data, but are not
            // declarations when they lie beyond the parent's primary table.
            boolean parentDeclarationIsEmitted =
                    parentSlot < parent.getVtableCount() || parentFunction.isOverride();
            boolean isOverride = parentDeclarationIsEmitted && isDeclaredBy(childFunction, child);
            Util.NamespacedString functionName =
                    isOverride ? childFunction.getName() : parentFunction.getName();
            FunctionContainer synchronizedFunction =
                    new FunctionContainer(
                            address,
                            functionName,
                            parentFunction.getCallingConvention(),
                            parentFunction.getReturnType(),
                            parentFunction.getParameters(),
                            isOverride,
                            parentFunction.isStatic());
            synchronizedFunction.setVarargs(parentFunction.isVarargs());
            copyAnalysis(childFunction, synchronizedFunction);
            child.getVirtualFunctions().put(childSlot, synchronizedFunction);
        }

        return childSlot;
    }

    private static boolean isDeclaredBy(FunctionContainer function, ClassContainer owner) {
        return hasDeclaration(function) && function.getName().parent().equals(owner.getName());
    }

    private static FunctionContainer copyDeclaration(
            FunctionContainer source, long address, Util.NamespacedString name) {
        FunctionContainer copy =
                new FunctionContainer(
                        address,
                        name,
                        source.getCallingConvention(),
                        source.getReturnType(),
                        source.getParameters(),
                        source.isOverride(),
                        source.isStatic());
        copy.setVarargs(source.isVarargs());
        copyAnalysis(source, copy);
        return copy;
    }

    private static FunctionContainer copyInheritedDeclaration(
            FunctionContainer source, long address) {
        FunctionContainer copy =
                new FunctionContainer(
                        address,
                        source.getName(),
                        source.getCallingConvention(),
                        source.getReturnType(),
                        source.getParameters(),
                        false,
                        source.isStatic());
        copy.setVarargs(source.isVarargs());
        copyAnalysis(source, copy);
        return copy;
    }

    private static void copyAnalysis(FunctionContainer source, FunctionContainer target) {
        if (source == null) return;
        target.setImplementationAddress(source.getImplementationAddress());
        if (source.hasPureVirtualValue()) {
            target.setPureVirtual(source.isPureVirtual());
        } else if (source.getImplementationAddress() != 0) {
            // An analyzed non-pure target is authoritative too. This also clears purity inherited
            // from an abstract parent when a child supplies a concrete implementation.
            target.clearPureVirtualValue();
        }
    }

    private static ClassContainer findDirectParent(
            ClassContainer child, List<ClassContainer> classes) {
        return findDirectParents(child, classes).stream().findFirst().orElse(null);
    }

    private static List<ClassContainer> findDirectParents(
            ClassContainer child, List<ClassContainer> classes) {
        List<ClassContainer> parents =
                child.getParents().stream()
                        .map(
                                parentName ->
                                        classes.stream()
                                                .filter(
                                                        candidate ->
                                                                candidate
                                                                        .getName()
                                                                        .equals(parentName))
                                                .findFirst()
                                                .orElse(null))
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();

        return parents.stream()
                .filter(
                        candidate ->
                                parents.stream()
                                        .filter(other -> other != candidate)
                                        .noneMatch(
                                                other ->
                                                        other.getParents()
                                                                .contains(candidate.getName())))
                .toList();
    }

    private static boolean hasDeclaration(FunctionContainer function) {
        return function != null
                && !function.getName().toString().isEmpty()
                && !function.getName().toString().equals("undefined");
    }
}
