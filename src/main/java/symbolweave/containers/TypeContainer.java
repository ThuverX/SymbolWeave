package symbolweave.containers;

import symbolweave.Util;

public class TypeContainer {

    public static TypeContainer VOID =
            new TypeContainer(Util.NamespacedString.parse("void"), "", "", false);
    public static TypeContainer VOIDPTR =
            new TypeContainer(Util.NamespacedString.parse("void"), "", "*", false);

    private Util.NamespacedString name;
    private String prefix = "";
    private String suffix = "";
    private boolean isConst = false;

    public TypeContainer(
            Util.NamespacedString name, String prefix, String suffix, boolean isConst) {
        this.name = name;
        this.prefix = prefix;
        this.suffix = suffix;
        this.isConst = isConst;
    }

    public TypeContainer(Util.NamespacedString name) {
        this.name = name;
    }

    public Util.NamespacedString getName() {
        return name;
    }

    public void setName(Util.NamespacedString name) {
        this.name = name;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getSuffix() {
        return suffix;
    }

    public void setSuffix(String suffix) {
        this.suffix = suffix;
    }

    public boolean isConst() {
        return isConst;
    }

    public void setConst(boolean aConst) {
        isConst = aConst;
    }
}
