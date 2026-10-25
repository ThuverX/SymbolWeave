package symbolweave;

import java.nio.file.Path;

/** Command-line overrides; configuration defaults remain in ProjectConfig. */
final class CommandLine {
    static final String USAGE =
            "Usage: java SymbolWeave.java [-c file] [--analyze|--no-analyze] [--fresh] [--bsim]"
                    + " [--signatures] [--pdb] [-o directory] [--exe file] [--vtable-check]"
                    + " [--print-config]";
    Path configFile;
    Boolean analyze;
    boolean fresh;
    boolean bsim;
    boolean signatures;
    boolean pdb;
    boolean vtableCheck;
    boolean printConfig;
    boolean help;
    Path executable;
    Path output;

    private CommandLine() {}

    static CommandLine parse(String[] args) {
        CommandLine result = new CommandLine();
        for (int i = 0; i < args.length; i++)
            switch (args[i]) {
                case "-c", "--config" -> result.configFile = Path.of(value(args, ++i, "--config"));
                case "-a", "--analyze" -> result.analyze = true;
                case "--no-analyze" -> result.analyze = false;
                case "-f", "--fresh" -> result.fresh = true;
                case "-b", "--bsim" -> result.bsim = true;
                case "-s", "--signatures" -> result.signatures = true;
                case "-pdb", "--pdb" -> result.pdb = true;
                case "-vt", "--vtable-check", "vtable-check" -> result.vtableCheck = true;
                case "--print-config", "--validate-config" -> result.printConfig = true;
                case "--exe" ->
                        result.executable =
                                Path.of(value(args, ++i, "--exe")).toAbsolutePath().normalize();
                case "-o", "--output" ->
                        result.output =
                                Path.of(value(args, ++i, "--output")).toAbsolutePath().normalize();
                case "-h", "--help" -> {
                    result.help = true;
                    return result;
                }
                default -> throw new IllegalArgumentException("Unknown argument: " + args[i]);
            }
        return result;
    }

    Path selectedConfig() {
        return configFile == null ? ProjectConfig.discover(Path.of("")) : configFile;
    }

    void apply(ProjectConfig config) {
        if (analyze != null) config.analyze = analyze;
        if (output != null) config.outputs.headers = output.toString();
        if (executable != null) {
            if (config.outputs.executable == null)
                throw new IllegalArgumentException(
                        "--exe requires outputs.executable to identify the target input");
            config.input(config.outputs.executable).executable = executable.toString();
        }
        config.outputs.signatures |= signatures;
        config.outputs.pdb |= pdb;
        config.bsim.enabled |= bsim;
        config.validate();
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException(option + " requires a value");
        return args[index];
    }
}
