package symbolweave;

import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.QueryResponseRecord;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ReferenceManager;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class BsimAnalyzer {
    public static void generateDatabase(
            GhidraWorkspace workspace, Path databasePath, ProjectConfig.Bsim settings)
            throws Exception {
        FunctionDatabase database =
                BSimClientFactory.buildClient(databasePath.toUri().toURL(), false);
        GenSignatures gen = null;
        try {
            if (!Files.exists(Path.of(databasePath + ".mv.db"))) {
                CreateDatabase command = new CreateDatabase();
                command.info = new DatabaseInformation();
                command.info.databasename = settings.databaseName;
                command.config_template = settings.template;
                command.info.trackcallgraph = settings.trackCallgraph;
                ResponseInfo response = command.execute(database);

                if (response == null) {
                    throw new IOException(database.getLastError().message);
                }
            }

            if (!database.initialize()) {
                throw new IllegalStateException(
                        "Failed to initialize BSim database: " + database.getLastError());
            }

            QueryExeInfo info = new QueryExeInfo();
            QueryResponseRecord response = database.query(info);

            if (response == null)
                throw new IOException(
                        "Failed to inspect BSim database: " + database.getLastError());
            if (info.exeresponse.recordCount > 0) {
                String md5 = workspace.getProgram().getExecutableMD5();
                if (info.exeresponse.records.stream()
                        .anyMatch(record -> record.getMd5().equalsIgnoreCase(md5))) return;
                throw new IOException(
                        "BSim database belongs to a different executable; choose another"
                                + " bsim.database path: "
                                + databasePath);
            }

            gen = new GenSignatures(false);

            gen.setVectorFactory(database.getLSHVectorFactory());

            gen.openProgram(workspace.getProgram(), null, null, null, null, null);

            gen.scanFunctions(
                    workspace.getProgram().getFunctionManager().getFunctions(true),
                    workspace.getProgram().getFunctionManager().getFunctionCount(),
                    Main.MONITOR);

            InsertRequest request = new InsertRequest();
            request.manage = gen.getDescriptionManager();

            response = database.query(request);

            if (response == null) {
                throw new IllegalStateException(
                        "Failed to insert BSim signatures: " + database.getLastError());
            }
        } finally {
            if (gen != null) gen.dispose();
            database.close();
        }
    }

    private static double numeric(String value) {
        return value.startsWith("0x")
                ? Long.parseUnsignedLong(value.substring(2), 16)
                : Double.parseDouble(value);
    }

    private static FunctionDatabase loadDatabase(Path databasePath, ProjectConfig.Bsim settings)
            throws Exception {
        FunctionDatabase database =
                BSimClientFactory.buildClient(databasePath.toUri().toURL(), false);

        if (!Files.exists(Path.of(databasePath + ".mv.db"))) {
            throw new IllegalStateException("BSim database does not exist: " + databasePath);
        }

        if (!database.initialize()) {
            throw new IllegalStateException(
                    "Failed to initialize BSim database: " + database.getLastError());
        }

        System.out.println("Loaded database from " + databasePath);

        return database;
    }

    public static void matchFunctions(
            GhidraWorkspace workspace,
            Path databasePath,
            ProjectConfig.Bsim settings,
            java.util.List<SymbolMapLoader.Entry> mapEntries,
            Path outputPath)
            throws Exception {
        FunctionDatabase db = loadDatabase(databasePath, settings);
        GenSignatures gen = null;
        try {

            gen = new GenSignatures(false);

            gen.setVectorFactory(db.getLSHVectorFactory());

            gen.openProgram(workspace.getProgram(), null, null, null, null, null);

            gen.scanFunctions(
                    workspace.getProgram().getFunctionManager().getFunctions(true),
                    workspace.getProgram().getFunctionManager().getFunctionCount(),
                    Main.MONITOR);

            QueryNearest query = new QueryNearest();

            query.manage = gen.getDescriptionManager();
            query.max = settings.maxMatches;
            query.thresh = settings.similarity;
            query.signifthresh = settings.significance;

            QueryResponseRecord response = db.query(query);

            if (response == null) {
                throw new IllegalStateException("Failed to scan functions: " + db.getLastError());
            }

            Element root = new Element("Functions");
            Document document = new Document(root);

            var excluded = java.util.regex.Pattern.compile(settings.excludeUnitRegex);
            var excludedAddresses =
                    mapEntries.stream()
                            .filter(e -> excluded.matcher(e.unit).find())
                            .map(e -> e.address)
                            .collect(java.util.stream.Collectors.toSet());

            for (SimilarityResult result : query.nearresponse.result) {
                FunctionDescription target = result.getBase();

                for (SimilarityNote note : result) {
                    FunctionDescription source = note.getFunctionDescription();

                    Address targetAddress =
                            workspace
                                    .getProgram()
                                    .getAddressFactory()
                                    .getDefaultAddressSpace()
                                    .getAddress(target.getAddress());

                    Function fn =
                            workspace
                                    .getProgram()
                                    .getFunctionManager()
                                    .getFunctionAt(targetAddress);

                    if (fn == null || settings.excludeExternal && fn.isExternal()) {
                        continue;
                    }

                    if (settings.excludeLibrary && fn.isLibrary()) {
                        continue;
                    }

                    ReferenceManager referenceManager =
                            workspace.getProgram().getReferenceManager();

                    int xrefs = referenceManager.getReferenceCountTo(fn.getEntryPoint());

                    if (excludedAddresses.contains(source.getAddress())) {
                        continue;
                    }

                    if (xrefs < settings.minReferences) continue;

                    long size = fn.getBody().getNumAddresses();

                    root.addContent(
                            new Element("Function")
                                    .setAttribute(
                                            "from", "0x" + Long.toHexString(source.getAddress()))
                                    .setAttribute(
                                            "to", "0x" + Long.toHexString(target.getAddress()))
                                    .setAttribute("size", Long.toString(size))
                                    .setAttribute(
                                            "similarity", Double.toString(note.getSimilarity()))
                                    .setAttribute(
                                            "significance",
                                            Double.toString(note.getSignificance())));
                }
            }

            root.sortChildren(
                    (e1, e2) -> {
                        double s1 = numeric(e1.getAttributeValue(settings.sortBy));
                        double s2 = numeric(e2.getAttributeValue(settings.sortBy));
                        return Double.compare(s2, s1);
                    });

            Files.createDirectories(outputPath.getParent());

            XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());

            try (OutputStream out = Files.newOutputStream(outputPath)) {
                outputter.output(document, out);
            }
        } finally {
            if (gen != null) gen.dispose();
            db.close();
        }
    }
}
