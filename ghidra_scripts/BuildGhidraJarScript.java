/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Builds ghidra for symbolweave
// @category Examples

import generic.jar.ApplicationModule;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.util.GhidraJarBuilder;

import java.io.File;
import java.util.List;

public class BuildGhidraJarScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        GhidraJarBuilder builder = new GhidraJarBuilder(Application.getApplicationLayout());

        builder.setMainClass("ghidra.JarRun");

        String[] modules = getScriptArgs();
        if (modules.length > 0) {
            builder.removeAllProcessorModules();
            for (String module : modules) builder.addModule(module);
        }
        // Without arguments, retain installed modules so configured languages/loaders remain
        // available.

        List<ApplicationModule> moduleList = builder.getIncludedModules();
        for (ApplicationModule module : moduleList) {
            println("Include: " + module.getName());
        }

        builder.addExcludedFileExtension(".htm");
        builder.addExcludedFileExtension(".html");
        builder.addExcludedFileExtension(".pdf");

        File installDir = Application.getInstallationDirectory().getFile(true);
        File file = new File(installDir, "ghidra.jar");
        builder.buildJar(file, null, monitor);

        println("Finished writing jar: " + file);
    }
}
