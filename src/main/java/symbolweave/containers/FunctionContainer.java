package symbolweave.containers;

import symbolweave.Util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class FunctionContainer {
    public enum CallingConvention {
        CDECL("__cdecl"),
        STDCALL("__stdcall"),
        THISCALL("__thiscall"),
        FASTCALL("__fastcall");

        private String name;

        CallingConvention(String name) {
            this.name = name;
        }

        public static CallingConvention forName(String callingConventionName) {
            return Arrays.stream(values())
                    .filter(c -> c.name.equals(callingConventionName))
                    .findFirst()
                    .orElse(null);
        }

        public String getName() {
            return this.name;
        }
    }

    private long address = 0;
    private Util.NamespacedString name;
    private CallingConvention callingConvention = CallingConvention.THISCALL;
    private TypeContainer returnType = TypeContainer.VOID;
    private Map<Integer, ParameterContainer> parameters = new HashMap<>();
    private boolean isOverride = false;
    private boolean isStatic = false;
    private boolean isVarargs = false;
    // Nullable so patches can distinguish an omitted value from an explicit false override.
    private Boolean isPureVirtual = null;
    // Callable target stored in the vtable. `address` may instead identify the slot itself.
    private long implementationAddress = 0;
    // Physical base subobject whose vtable owns this entry after multiple-inheritance flattening.
    // The generated class remains the metadata owner; this only controls the raw receiver type.
    private Util.NamespacedString vtableOwner = null;
    // For loose functions declared by a patch, this is the generated header stem.
    private String headerFile = "";

    public FunctionContainer(
            long address,
            Util.NamespacedString name,
            CallingConvention callingConvention,
            TypeContainer returnType,
            Map<Integer, ParameterContainer> parameters,
            boolean isOverride,
            boolean isStatic) {
        this.address = address;
        this.name = name;
        this.callingConvention = callingConvention;
        this.returnType = returnType;
        this.parameters = parameters;
        this.isOverride = isOverride;
        this.isStatic = isStatic;
    }

    public FunctionContainer(Util.NamespacedString name) {
        this.name = name;
    }

    public long getAddress() {
        return address;
    }

    public void setAddress(long address) {
        this.address = address;
    }

    public Util.NamespacedString getName() {
        return name;
    }

    public void setName(Util.NamespacedString name) {
        this.name = name;
    }

    public CallingConvention getCallingConvention() {
        return callingConvention;
    }

    public void setCallingConvention(CallingConvention callingConvention) {
        this.callingConvention = callingConvention;
    }

    public TypeContainer getReturnType() {
        return returnType;
    }

    public void setReturnType(TypeContainer returnType) {
        this.returnType = returnType;
    }

    public Map<Integer, ParameterContainer> getParameters() {
        return parameters;
    }

    public void setParameters(Map<Integer, ParameterContainer> parameters) {
        this.parameters = parameters;
    }

    public boolean isOverride() {
        return isOverride;
    }

    public void setOverride(boolean override) {
        isOverride = override;
    }

    public boolean isStatic() {
        return isStatic;
    }

    public void setStatic(boolean aStatic) {
        isStatic = aStatic;
    }

    public boolean isVarargs() {
        return isVarargs;
    }

    public void setVarargs(boolean varargs) {
        isVarargs = varargs;
    }

    public boolean isPureVirtual() {
        return Boolean.TRUE.equals(isPureVirtual);
    }

    public boolean hasPureVirtualValue() {
        return isPureVirtual != null;
    }

    public void setPureVirtual(boolean pureVirtual) {
        isPureVirtual = pureVirtual;
    }

    public void clearPureVirtualValue() {
        isPureVirtual = null;
    }

    public long getImplementationAddress() {
        return implementationAddress;
    }

    public void setImplementationAddress(long implementationAddress) {
        this.implementationAddress = implementationAddress;
    }

    public Util.NamespacedString getVtableOwner() {
        return vtableOwner;
    }

    public void setVtableOwner(Util.NamespacedString vtableOwner) {
        this.vtableOwner = vtableOwner;
    }

    public String getHeaderFile() {
        return headerFile;
    }

    public void setHeaderFile(String headerFile) {
        this.headerFile = headerFile == null ? "" : headerFile;
    }
}
