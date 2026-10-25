package symbolweave.containers;

public class ParameterContainer {
    private String name;
    private TypeContainer type;

    public ParameterContainer(String name, TypeContainer type) {
        this.name = name;
        this.type = type;
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
}
