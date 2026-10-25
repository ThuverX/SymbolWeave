package symbolweave.containers;

public class MemberContainer {
    private String name;
    private TypeContainer type = TypeContainer.VOIDPTR;
    private String value = "";
    private boolean isStatic = false;
    private long arraySize = 0;
    private long size = 0;
    private Long offset;
    private Long address;

    public MemberContainer(String name, TypeContainer type, String value, boolean isStatic) {
        this.name = name;
        this.type = type;
        this.value = value;
        this.isStatic = isStatic;
    }

    public MemberContainer(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public TypeContainer getType() {
        return type;
    }

    public void setType(TypeContainer type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean isStatic() {
        return isStatic;
    }

    public void setStatic(boolean aStatic) {
        isStatic = aStatic;
    }

    public long getSize() {
        return size;
    }

    public long getArraySize() {
        return arraySize;
    }

    public void setArraySize(long arraySize) {
        this.arraySize = arraySize;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public Long getOffset() {
        return offset;
    }

    public void setOffset(Long offset) {
        this.offset = offset;
    }

    public Long getAddress() {
        return address;
    }

    public void setAddress(Long address) {
        this.address = address;
    }

    public boolean isAddressed() {
        return address != null;
    }
}
