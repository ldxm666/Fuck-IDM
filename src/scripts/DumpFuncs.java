import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class DumpFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.setOptions(di.getOptions());
        di.openProgram(currentProgram);
        String[] args = getScriptArgs();
        for (String a : args) {
            long va = Long.parseLong(a.replace("0x", ""), 16);
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            Function f = getFunctionAt(addr);
            if (f == null) f = getFunctionContaining(addr);
            println("");
            println("################################################################");
            println("##### " + a + "  ->  " + (f == null ? "<no function>" : f.getName() + " @ " + f.getEntryPoint()));
            println("################################################################");
            if (f == null) continue;
            DecompileResults res = di.decompileFunction(f, 90, monitor);
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("!! decompile failed: " + (res == null ? "null" : res.getErrorMessage()));
            }
            // show who references this function
            ReferenceManager rm = currentProgram.getReferenceManager();
            StringBuilder sb = new StringBuilder();
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                sb.append("  ").append(r.getFromAddress()).append(" (").append(r.getReferenceType()).append(")\n");
            }
            println("---- references to entry: ----");
            println(sb.length() == 0 ? "  (none)" : sb.toString());
        }
        di.dispose();
    }
}
