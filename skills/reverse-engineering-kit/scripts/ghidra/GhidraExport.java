// Export functions, imports, strings and decompiled code for run_ghidra.py as one JSON file.
// Written in Java so that any Ghidra 12 install can run it: Ghidra compiles it itself, with no
// PyGhidra or Jython setup.
// Arguments: <output.json> <top N> [function name or address | bytes:<symbol or address>:<count>]
//@category ReverseEngineeringKit

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.DefinedStringIterator;

public class GhidraExport extends GhidraScript {
    private static final int DECOMPILE_SECONDS = 60;
    private static final int MAX_FUNCTIONS = 5000;
    private static final int MAX_STRINGS = 3000;
    private static final int MAX_TEXT = 300;
    private static final int MAX_CODE = 60000;
    private static final int MAX_LISTED = 20;
    private static final int MAX_BYTES = 4096;
    private static final Set<String> ENTRY_NAMES =
        Set.of("main", "wmain", "WinMain", "wWinMain", "DllMain");

    private final Map<Address, Integer> stringUses = new HashMap<>();
    private final Map<Address, Set<String>> importUses = new HashMap<>();
    private final Map<Address, Integer> callerCounts = new HashMap<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File output = new File(args[0]);
        int top = Integer.parseInt(args[1]);
        JsonObject result = new JsonObject();
        result.add("program", describeProgram());
        result.add("strings", exportStrings());
        result.add("imports", exportImports());
        List<Function> ranked = rankFunctions();
        result.add("functions", exportFunctions(ranked));
        JsonArray missing = new JsonArray();
        result.add("decompiled", decompile(choose(ranked, top, args, missing)));
        result.add("bytes", readBytes(args, missing));
        result.add("missing", missing);
        write(output, result);
    }

    private JsonObject describeProgram() {
        JsonObject program = new JsonObject();
        program.addProperty("name", clip(currentProgram.getName(), MAX_TEXT));
        program.addProperty("format", currentProgram.getExecutableFormat());
        program.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        program.addProperty(
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        program.addProperty("image_base", currentProgram.getImageBase().toString());
        program.addProperty("sha256", currentProgram.getExecutableSHA256());
        return program;
    }

    private JsonObject exportStrings() {
        JsonArray items = new JsonArray();
        int total = 0;
        DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram);
        while (strings.hasNext()) {
            Data data = strings.next();
            if (!(data.getValue() instanceof String text)) {
                continue;
            }
            total++;
            Set<String> users = new LinkedHashSet<>();
            for (Reference reference : getReferencesTo(data.getAddress())) {
                Function user = getFunctionContaining(reference.getFromAddress());
                if (user != null) {
                    users.add(clip(user.getName(), MAX_TEXT));
                    stringUses.merge(user.getEntryPoint(), 1, Integer::sum);
                }
            }
            if (items.size() < MAX_STRINGS) {
                JsonObject item = new JsonObject();
                item.addProperty("address", data.getAddress().toString());
                item.addProperty("value", clip(text, MAX_TEXT));
                item.add("functions", array(users));
                items.add(item);
            }
        }
        return section(total, items);
    }

    private JsonObject exportImports() throws Exception {
        FunctionManager manager = currentProgram.getFunctionManager();
        JsonArray items = new JsonArray();
        int total = 0;
        for (Function external : manager.getExternalFunctions()) {
            total++;
            Set<String> callers = new LinkedHashSet<>();
            List<Function> targets = new ArrayList<>();
            targets.add(external);
            Address[] thunks = external.getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address address : thunks) {
                    Function thunk = getFunctionAt(address);
                    if (thunk != null) {
                        targets.add(thunk);
                    }
                }
            }
            for (Function target : targets) {
                for (Function caller : target.getCallingFunctions(monitor)) {
                    if (caller.isThunk()) {
                        continue;
                    }
                    callers.add(clip(caller.getName(), MAX_TEXT));
                    importUses.computeIfAbsent(caller.getEntryPoint(), key -> new LinkedHashSet<>())
                        .add(external.getName());
                }
            }
            JsonObject item = new JsonObject();
            item.addProperty("name", clip(external.getName(), MAX_TEXT));
            var location = external.getExternalLocation();
            item.addProperty("library", location == null ? "" : location.getLibraryName());
            item.add("callers", array(callers));
            items.add(item);
        }
        return section(total, items);
    }

    private List<Function> rankFunctions() throws Exception {
        List<Function> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isThunk() || function.isExternal()) {
                continue;
            }
            callerCounts.put(function.getEntryPoint(), function.getCallingFunctions(monitor).size());
            functions.add(function);
        }
        functions.sort(Comparator.comparingInt((Function function) -> -score(function))
            .thenComparingLong(function -> -function.getBody().getNumAddresses()));
        return functions;
    }

    // Application logic tends to use strings and library calls; compiler stubs use neither.
    private int score(Function function) {
        Address entry = function.getEntryPoint();
        int value = 3 * stringUses.getOrDefault(entry, 0);
        value += 2 * importUses.getOrDefault(entry, Set.of()).size();
        value += Math.min(callerCounts.getOrDefault(entry, 0), 5);
        return ENTRY_NAMES.contains(function.getName()) ? value + 1_000_000 : value;
    }

    private JsonObject exportFunctions(List<Function> ranked) throws Exception {
        JsonArray items = new JsonArray();
        for (Function function : ranked.subList(0, Math.min(ranked.size(), MAX_FUNCTIONS))) {
            Address entry = function.getEntryPoint();
            Set<String> callees = new LinkedHashSet<>();
            for (Function callee : function.getCalledFunctions(monitor)) {
                callees.add(clip(callee.getName(), MAX_TEXT));
            }
            JsonObject item = new JsonObject();
            item.addProperty("name", clip(function.getName(), MAX_TEXT));
            item.addProperty("address", entry.toString());
            item.addProperty("size", function.getBody().getNumAddresses());
            item.addProperty("callers", callerCounts.getOrDefault(entry, 0));
            item.addProperty("strings", stringUses.getOrDefault(entry, 0));
            item.add("imports", array(importUses.getOrDefault(entry, Set.of())));
            item.add("callees", array(callees));
            items.add(item);
        }
        return section(ranked.size(), items);
    }

    private Set<Function> choose(List<Function> ranked, int top, String[] args, JsonArray missing) {
        Set<Function> chosen = new LinkedHashSet<>();
        boolean named = false;
        for (int index = 2; index < args.length; index++) {
            if (args[index].startsWith("bytes:")) {
                continue;
            }
            named = true;
            List<Function> matches = getGlobalFunctions(args[index]);
            Function function = matches.isEmpty() ? atAddress(args[index]) : matches.get(0);
            if (function == null) {
                missing.add(args[index]);
            } else {
                chosen.add(function);
            }
        }
        if (!named) {
            chosen.addAll(ranked.subList(0, Math.min(ranked.size(), top)));
        }
        return chosen;
    }

    private JsonArray readBytes(String[] args, JsonArray missing) {
        JsonArray items = new JsonArray();
        for (int index = 2; index < args.length; index++) {
            if (!args[index].startsWith("bytes:")) {
                continue;
            }
            String[] parts = args[index].split(":");
            int count = Math.min(Integer.parseInt(parts[2]), MAX_BYTES);
            Address address = symbolOrAddress(parts[1]);
            byte[] data = new byte[count];
            int read = 0;
            if (address != null) {
                try {
                    read = currentProgram.getMemory().getBytes(address, data);
                } catch (Exception error) {
                    read = 0;
                }
            }
            if (read <= 0) {
                missing.add(parts[1]);
                continue;
            }
            StringBuilder hex = new StringBuilder();
            for (int offset = 0; offset < read; offset++) {
                hex.append(String.format(offset == 0 ? "%02x" : " %02x", data[offset] & 0xff));
            }
            JsonObject item = new JsonObject();
            item.addProperty("name", clip(parts[1], MAX_TEXT));
            item.addProperty("address", address.toString());
            item.addProperty("hex", hex.toString());
            items.add(item);
        }
        return items;
    }

    private Address symbolOrAddress(String text) {
        var symbols = currentProgram.getSymbolTable().getGlobalSymbols(text);
        if (!symbols.isEmpty()) {
            return symbols.get(0).getAddress();
        }
        try {
            return toAddr(text);
        } catch (RuntimeException error) {
            return null;
        }
    }

    private Function atAddress(String text) {
        try {
            Address address = toAddr(text);
            return address == null ? null : getFunctionContaining(address);
        } catch (RuntimeException error) {
            return null;
        }
    }

    private JsonArray decompile(Set<Function> chosen) {
        JsonArray items = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (Function function : chosen) {
                JsonObject item = new JsonObject();
                item.addProperty("name", clip(function.getName(), MAX_TEXT));
                item.addProperty("address", function.getEntryPoint().toString());
                DecompileResults results =
                    decompiler.decompileFunction(function, DECOMPILE_SECONDS, monitor);
                if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                    item.addProperty("code", clip(results.getDecompiledFunction().getC(), MAX_CODE));
                } else {
                    item.addProperty("error", clip(results.getErrorMessage(), MAX_TEXT));
                }
                items.add(item);
            }
        } finally {
            decompiler.dispose();
        }
        return items;
    }

    private static JsonObject section(int total, JsonArray items) {
        JsonObject section = new JsonObject();
        section.addProperty("total", total);
        section.add("items", items);
        return section;
    }

    private static JsonArray array(Set<String> values) {
        JsonArray array = new JsonArray();
        for (String value : values) {
            if (array.size() == MAX_LISTED) {
                break;
            }
            array.add(value);
        }
        return array;
    }

    // Target text can hold lone surrogates, which would stop the UTF-8 writer.
    private static String clip(String text, int limit) {
        if (text == null) {
            return "";
        }
        String valid = new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        return valid.length() > limit ? valid.substring(0, limit) : valid;
    }

    private static void write(File output, JsonObject result) throws Exception {
        File temporary = new File(output.getPath() + ".tmp");
        String text = new GsonBuilder().disableHtmlEscaping().create().toJson(result);
        Files.writeString(temporary.toPath(), text, StandardCharsets.UTF_8);
        Files.move(temporary.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
}
