package symbolweave;

import symbolweave.containers.FileContainer;

import java.nio.file.*;
import java.util.*;

/** Runs extraction, matching, merge, and export in configured order. */
final class GenerationPipeline {
    private final ProjectConfig config;
    private final PluginRegistry plugins;

    GenerationPipeline(ProjectConfig config, PluginRegistry plugins) {
        this.config = config;
        this.plugins = plugins;
    }

    void run(boolean fresh, boolean check) throws Exception {
        if (check) {
            VtableChecker.configure(config);
            VtableChecker.run(config.path(config.outputs.xml), config.path(config.outputs.headers));
            return;
        }
        validateInputs();
        var containers = loadInputs(fresh);
        if (config.bsim.enabled) runBsim(config);
        match(containers);
        writeOutputs(merge(containers));
    }

    private void validateInputs() throws Exception {
        for (var input : config.inputs) {
            Path required =
                    config.path(
                            config.analyze && !input.extractors.isEmpty()
                                    ? input.executable
                                    : input.xml);
            if (!Files.isRegularFile(required))
                throw new IllegalArgumentException("Missing input " + input.id + ": " + required);
            if (config.analyze)
                for (var extractor : input.extractors)
                    if (extractor.plugin.equals("map")) {
                        Path map = config.path(Options.required(extractor.options, "file"));
                        if (!Files.isRegularFile(map))
                            throw new IllegalArgumentException("Missing map input: " + map);
                    }
        }
    }

    private Map<String, FileContainer> loadInputs(boolean fresh) throws Exception {
        Map<String, FileContainer> containers = new LinkedHashMap<>();
        for (var input : config.inputs) {
            Path xml = config.path(input.xml);
            if (config.analyze && !input.extractors.isEmpty()) {
                System.out.println("Analyzing " + input.id);
                List<ConfigurableMerger.Layer> extracted = new ArrayList<>();
                try (var workspace = GhidraWorkspace.open(config, input, fresh)) {
                    for (var extractor : input.extractors) {
                        System.out.println("  Extracting " + extractor.plugin);
                        extracted.add(
                                new ConfigurableMerger.Layer(
                                        plugins.get(extractor.plugin)
                                                .extract(
                                                        config,
                                                        input,
                                                        workspace,
                                                        extractor.options),
                                        false));
                    }
                }
                FileContainer result;
                if (extracted.size() == 1) result = extracted.getFirst().container();
                else {
                    var settings = new ProjectConfig.Merge();
                    settings.backfillDeclarations = false;
                    settings.synchronizePrimary = false;
                    settings.synchronizeSecondary = false;
                    result = ConfigurableMerger.merge(extracted, settings);
                }
                writeXml(result, xml);
            }
            if (!Files.isRegularFile(xml))
                throw new IllegalArgumentException(
                        "Missing input XML: " + xml + "; enable analyze or supply the XML");
            containers.put(input.id, DataXMLSerializer.readContainerFromFile(xml));
        }
        return containers;
    }

    private void match(Map<String, FileContainer> containers) throws Exception {
        for (var rule : config.matching) {
            System.out.println(
                    "Matching " + rule.source + " -> " + rule.target + " with " + rule.plugin);
            plugins.get(rule.plugin).match(config, rule, containers);
        }
    }

    private FileContainer merge(Map<String, FileContainer> containers) throws Exception {
        List<ConfigurableMerger.Layer> layers = new ArrayList<>();
        for (String id : config.merge.sources)
            layers.add(
                    new ConfigurableMerger.Layer(
                            containers.get(id), false, config.merge.sourcePolicies.get(id)));
        for (var patch : config.merge.patches)
            for (Path file : patchFiles(config, patch)) {
                System.out.println("Applying patch " + file);
                FileContainer data = DataXMLSerializer.readContainerFromFile(file);
                if (patch.headerFromFilename) {
                    String name = file.getFileName().toString().replaceFirst("\\.[^.]+$", "");
                    for (var fn : data.getLooseFunctions())
                        if (fn.getName().isTopLevel()) {
                            fn.setHeaderFile(name);
                            XmlPresence.supplied(fn, "headerFile");
                        }
                }
                layers.add(new ConfigurableMerger.Layer(data, true, patch.policy));
            }
        Map<String, PortableExecutable> images = new HashMap<>();
        return ConfigurableMerger.merge(
                layers,
                config.merge,
                (merged, settings) -> {
                    String from = settings.resolveVirtualFunctionAddressesFrom;
                    if (from == null || from.isBlank()) return;
                    PortableExecutable image = images.get(from);
                    if (image == null) {
                        image =
                                PortableExecutable.readImage(
                                        config.path(config.input(from).executable));
                        images.put(from, image);
                    }
                    var resolution = VirtualFunctionAddressResolver.resolve(merged, image);
                    System.out.println(
                            "Vtable addresses from "
                                    + from
                                    + ": slots="
                                    + resolution.slots()
                                    + "; implementations="
                                    + resolution.implementations()
                                    + "; unreadable="
                                    + resolution.unreadable());
                });
    }

    private void writeOutputs(FileContainer merged) throws Exception {
        SDKWriter.configure(config);
        SDKWriter.validateMembers(SDKWriter.collapseContainer(merged));
        merged.setGeneratedFor(config.outputs.generatedFor);
        writeXml(merged, config.path(config.outputs.xml));
        if (config.outputs.signatures || config.outputs.pdb) {
            var binary = config.input(config.outputs.executable);
            if (config.outputs.signatures) {
                var result =
                        SignatureDatabaseGenerator.generate(
                                merged,
                                config.path(binary.executable),
                                config.path(config.outputs.signatureDirectory),
                                config.outputs.signatureLabel);
                System.out.println(
                        "Signatures: " + result.path() + "; issues=" + result.issueCount());
            }
            if (config.outputs.pdb) {
                var result =
                        PdbGenerator.generate(
                                merged,
                                config.path(binary.executable),
                                config.path(config.outputs.pdbDirectory),
                                config.outputs.pdbModule);
                System.out.println("PDB: " + result.path());
            }
        }
        SDKWriter.writeToDirectory(
                SDKWriter.collapseContainer(merged),
                config.path(config.outputs.headers),
                config.outputs.supportHeaders.stream().map(config::path).toList());
        System.out.println("SDK XML: " + config.path(config.outputs.xml));
        System.out.println("Headers: " + config.path(config.outputs.headers));
    }

    static void writeXml(FileContainer data, Path path) throws Exception {
        Files.createDirectories(path.toAbsolutePath().getParent());
        DataXMLSerializer.writeContainerToFile(data, path);
    }

    static List<Path> patchFiles(ProjectConfig config, ProjectConfig.Patch patch) throws Exception {
        List<Path> files = new ArrayList<>();
        if (!patch.files.isEmpty()) for (String file : patch.files) files.add(config.path(file));
        else {
            Path directory = config.path(patch.directory);
            if (!Files.isDirectory(directory)) {
                if (patch.required)
                    throw new IllegalArgumentException("Missing patch directory: " + directory);
                return files;
            }
            var glob = FileSystems.getDefault().getPathMatcher("glob:" + patch.glob);
            try (var stream = Files.walk(directory, patch.recursive ? Integer.MAX_VALUE : 1)) {
                stream.filter(Files::isRegularFile)
                        .filter(f -> glob.matches(directory.relativize(f)))
                        .forEach(files::add);
            }
        }
        if (patch.order.equals("ascending")) files.sort(Comparator.comparing(Path::toString));
        else if (patch.order.equals("descending"))
            files.sort(Comparator.comparing(Path::toString).reversed());
        else if (patch.files.isEmpty())
            throw new IllegalArgumentException("Patch order listed requires files");
        if (patch.required && files.isEmpty())
            throw new IllegalArgumentException(
                    "No patch files matched " + patch.directory + "/" + patch.glob);
        return files;
    }

    private static void runBsim(ProjectConfig config) throws Exception {
        var settings = config.bsim;
        config.input(settings.source);
        config.input(settings.target);
        Path database = config.path(settings.database);
        Files.createDirectories(database.getParent());
        try (var workspace = GhidraWorkspace.open(config, config.input(settings.source), false)) {
            BsimAnalyzer.generateDatabase(workspace, database, settings);
        }
        List<SymbolMapLoader.Entry> entries = List.of();
        if (settings.mapInput != null) {
            var map =
                    config.input(settings.mapInput).extractors.stream()
                            .filter(e -> e.plugin.equals("map"))
                            .findFirst()
                            .orElseThrow(
                                    () ->
                                            new IllegalArgumentException(
                                                    "bsim.mapInput has no map extractor"));
            entries =
                    new SymbolMapLoader(
                                    config.path(Options.required(map.options, "file")), map.options)
                            .entries();
        }
        try (var workspace = GhidraWorkspace.open(config, config.input(settings.target), false)) {
            BsimAnalyzer.matchFunctions(
                    workspace, database, settings, entries, config.path(settings.output));
        }
    }
}
