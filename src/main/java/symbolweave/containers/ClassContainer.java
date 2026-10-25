package symbolweave.containers;

import symbolweave.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClassContainer {
    private Util.NamespacedString name;
    private long vtableAddress = 0;
    private int vtableCount = 0;
    private Map<Integer, FunctionContainer> virtualFunctions = new HashMap<>();
    private List<FunctionContainer> functions = new ArrayList<>();
    private List<Util.NamespacedString> parents = new ArrayList<>();
    private List<MemberContainer> members = new ArrayList<>();

    public ClassContainer(
            Util.NamespacedString name,
            long vtableAddress,
            int vtableCount,
            Map<Integer, FunctionContainer> virtualFunctions,
            List<FunctionContainer> functions,
            List<Util.NamespacedString> parents,
            List<MemberContainer> members) {
        this.name = name;
        this.vtableAddress = vtableAddress;
        this.vtableCount = vtableCount;
        this.virtualFunctions = virtualFunctions;
        this.functions = functions;
        this.parents = parents;
        this.members = members;
    }

    public ClassContainer(Util.NamespacedString name) {
        this.name = name;
    }

    public int getVtableCount() {
        return vtableCount;
    }

    public void setVtableCount(int vtableCount) {
        this.vtableCount = vtableCount;
    }

    public Util.NamespacedString getName() {
        return name;
    }

    public void setName(Util.NamespacedString name) {
        this.name = name;
    }

    public long getVtableAddress() {
        return vtableAddress;
    }

    public void setVtableAddress(long vtableAddress) {
        this.vtableAddress = vtableAddress;
    }

    public Map<Integer, FunctionContainer> getVirtualFunctions() {
        return virtualFunctions;
    }

    public void setVirtualFunctions(Map<Integer, FunctionContainer> virtualFunctions) {
        this.virtualFunctions = virtualFunctions;
    }

    public List<FunctionContainer> getFunctions() {
        return functions;
    }

    public void setFunctions(List<FunctionContainer> functions) {
        this.functions = functions;
    }

    public List<Util.NamespacedString> getParents() {
        return parents;
    }

    public void setParents(List<Util.NamespacedString> parents) {
        this.parents = parents;
    }

    public List<MemberContainer> getMembers() {
        return members;
    }

    public void setMembers(List<MemberContainer> members) {
        this.members = members;
    }
}
