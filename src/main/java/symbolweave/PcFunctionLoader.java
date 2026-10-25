package symbolweave;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;

import symbolweave.containers.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/** Reads PC symbols exclusively from the program's function list. */
public final class PcFunctionLoader {
    public FileContainer loadFromFunctions(GhidraWorkspace workspace) {
        return loadFromFunctions(workspace.getProgram());
    }

    public FileContainer loadFromFunctions(Program program) {
        FileContainer result = new FileContainer(program.getName());
        Map<Util.NamespacedString, ClassContainer> classes = new LinkedHashMap<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) continue;
            Namespace owner = function.getParentNamespace();
            boolean member = owner instanceof GhidraClass;
            var convention =
                    FunctionContainer.CallingConvention.forName(
                            function.getCallingConventionName());
            if (convention == null) convention = FunctionContainer.CallingConvention.CDECL;
            boolean instance =
                    member
                            && (convention == FunctionContainer.CallingConvention.THISCALL
                                    || java.util.Arrays.stream(function.getParameters())
                                            .anyMatch(
                                                    p ->
                                                            p.isAutoParameter()
                                                                    && p.getName().equals("this")));
            if (instance) convention = FunctionContainer.CallingConvention.THISCALL;
            Map<Integer, ParameterContainer> parameters = new LinkedHashMap<>();
            for (var parameter : function.getParameters()) {
                if (instance && parameter.isAutoParameter() && parameter.getName().equals("this"))
                    continue;
                parameters.put(
                        parameters.size(),
                        new ParameterContainer(
                                parameter.getName(), toType(parameter.getDataType())));
            }
            FunctionContainer converted =
                    new FunctionContainer(
                            function.getEntryPoint().getOffset(),
                            Util.NamespacedString.parse(function.getName(true)),
                            convention,
                            toType(function.getReturnType()),
                            parameters,
                            false,
                            member && !instance);
            converted.setVarargs(function.hasVarArgs());
            converted.setImplementationAddress(function.getEntryPoint().getOffset());
            if (member) {
                var name = Util.NamespacedString.parse(owner.getName(true));
                classes.computeIfAbsent(
                                name,
                                ignored ->
                                        new ClassContainer(
                                                name,
                                                0,
                                                0,
                                                new HashMap<>(),
                                                new ArrayList<>(),
                                                new ArrayList<>(),
                                                new ArrayList<>()))
                        .getFunctions()
                        .add(converted);
            } else {
                result.getLooseFunctions().add(converted);
            }
        }
        result.getClasses().addAll(classes.values());
        return result;
    }

    static TypeContainer toType(DataType dataType) {
        if (dataType instanceof TypeDef alias) return toType(alias.getBaseDataType());
        if (dataType instanceof Pointer pointer) {
            TypeContainer type =
                    pointer.getDataType() == null
                            ? new TypeContainer(Util.NamespacedString.parse("void"))
                            : toType(pointer.getDataType());
            type.setSuffix(type.getSuffix() + "*");
            return type;
        }
        String name = dataType.getName();
        if (dataType instanceof AbstractIntegerDataType integer
                && !name.equals("char")
                && !name.equals("wchar_t")) {
            int width = dataType.getLength() * 8;
            if (width == 8 || width == 16 || width == 32 || width == 64)
                name = "std::" + (integer.isSigned() ? "int" : "uint") + width + "_t";
        } else if (name.equals("undefined")) name = "undefined1";
        return new TypeContainer(Util.NamespacedString.parse(name));
    }
}
