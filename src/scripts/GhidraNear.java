import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class GhidraNear extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String a : getScriptArgs()) {
            long va = Long.parseLong(a.replace("0x", ""), 16);
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            Function c = fm.getFunctionContaining(addr);
            println("");
            println("#### probe " + a);
            println("   containing: " + (c == null ? "NONE" : c.getName() + " @" + c.getEntryPoint() + " body=" + c.getBody()));
            println("   functions near:");
            Address lo = addr.subtract(0x800);
            Address hi = addr.add(0x800);
            FunctionIterator it = fm.getFunctions(lo, true);
            int n = 0;
            while (it.hasNext() && n < 25) {
                Function g = it.next();
                if (g.getEntryPoint().compareTo(hi) > 0) break;
                println("      " + g.getEntryPoint() + "  " + g.getName() + "  size=" + g.getBody().getNumAddresses());
                n++;
            }
            println("   refs from " + a + ":");
            for (Reference r : rm.getReferencesFrom(addr)) {
                println("      -> " + r.getToAddress() + " (" + r.getReferenceType() + ")");
            }
        }
    }
}
