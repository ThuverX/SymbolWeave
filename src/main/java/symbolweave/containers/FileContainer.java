package symbolweave.containers;

import java.util.ArrayList;
import java.util.List;

public class FileContainer {

    private List<ClassContainer> classes = new ArrayList<>();
    private List<FunctionContainer> looseFunctions = new ArrayList<>();
    private String generatedFor;

    public FileContainer(String generatedFor) {
        this.generatedFor = generatedFor;
    }

    public List<ClassContainer> getClasses() {
        return classes;
    }

    public void setClasses(List<ClassContainer> classes) {
        this.classes = classes;
    }

    public String getGeneratedFor() {
        return generatedFor;
    }

    public void setGeneratedFor(String generatedFor) {
        this.generatedFor = generatedFor;
    }

    public List<FunctionContainer> getLooseFunctions() {
        return looseFunctions;
    }

    public void setLooseFunctions(List<FunctionContainer> looseFunctions) {
        this.looseFunctions = looseFunctions;
    }
}
