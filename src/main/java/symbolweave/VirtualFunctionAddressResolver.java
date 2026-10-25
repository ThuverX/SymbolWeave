package symbolweave;

import symbolweave.containers.FileContainer;

import java.io.IOException;

/** Fill missing virtual locations after a selected source or patch layer is merged. */
final class VirtualFunctionAddressResolver {
    record Result(int slots, int implementations, int unreadable) {}

    static Result resolve(FileContainer metadata, PortableExecutable image) {
        int slots = 0;
        int implementations = 0;
        int unreadable = 0;
        for (var cls : metadata.getClasses()) {
            for (var entry : cls.getVirtualFunctions().entrySet()) {
                var function = entry.getValue();
                if (function == null || entry.getKey() < 0) continue;
                if (function.getImplementationAddress() != 0) continue;
                long slot = function.getAddress();
                if (slot == 0) {
                    if (cls.getVtableAddress() == 0) continue;
                    // A flattened secondary slot needs its physical address, not the primary base.
                    if (function.getVtableOwner() != null
                            && !function.getVtableOwner().equals(cls.getName())) continue;
                    try {
                        slot =
                                Math.addExact(
                                        cls.getVtableAddress(),
                                        Math.multiplyExact(
                                                (long) entry.getKey(), image.pointerSize()));
                    } catch (ArithmeticException e) {
                        unreadable++;
                        continue;
                    }
                }
                try {
                    long implementation = image.readPointerAtVa(slot);
                    if (function.getAddress() == 0) {
                        function.setAddress(slot);
                        XmlPresence.supplied(function, "address");
                        slots++;
                    }
                    if (function.getImplementationAddress() == 0 && implementation != 0) {
                        function.setImplementationAddress(implementation);
                        XmlPresence.supplied(function, "implementationAddress");
                        implementations++;
                    }
                } catch (IOException e) {
                    unreadable++;
                    System.out.println(
                            "Cannot resolve "
                                    + cls.getName()
                                    + " slot "
                                    + entry.getKey()
                                    + ": "
                                    + e.getMessage());
                }
            }
        }
        return new Result(slots, implementations, unreadable);
    }
}
