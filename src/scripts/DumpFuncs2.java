import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class DumpFuncs2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String a : getScriptArgs()) {
            long va = Long.parseLong(a.replace("0x", ""), 16);
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            Function f = getFunctionAt(addr);
            if (f == null) f = getFunctionContaining(addr);
            if (f == null) {
                disassemble(addr);
                f = createFunction(addr, null);
                if (f == null) f = getFunctionContaining(addr);
            }
            println("");
            println("################ " + a + " -> " + (f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint()));
            if (f == null) continue;
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("!! decompile failed: " + (res == null ? "null" : res.getErrorMessage()));
            }
            StringBuilder sb = new StringBuilder();
            ReferenceManager rm = currentProgram.getReferenceManager();
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                sb.append("   ").append(r.getFromAddress()).append(" (").append(r.getReferenceType()).append(")\n");
            }
            println("---- refs to entry ----");
            println(sb.length() == 0 ? "   (none)" : sb.toString());
        }
        di.dispose();
    }
}
