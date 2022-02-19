# This script will get all data for cvars and return it in json.
# It returns: Name, Description, Default Value, Flags, Min, Max
#
# To use: Make sure the RegisterCvar function is named RegisterCvar. Then run script.
#
# In the process, it will do the following fixes:
# * Create a function where RegisterCvar is if it isn't already one
# * Set string datatype for name, description, default value
# * Set min and max to float datatype


import json
import ghidra.app.decompiler as decomp

class CvarEntry(dict):
    def __init__(self):
        dict.__init__(self,name=None,description=None,defaultValue=None,flags=None)
 

def SortByName(e):
    return e["name"]


# Finds the function entry and creates it
def FindAndCreateFunctionForAddress(addr):
    codeUnits = currentProgram.getListing().getCodeUnits(addr, False)
    codeUnits.next()
    codeUnit = codeUnits.next()
    while getSymbolAt(codeUnit.getAddress()) is None:
        previousCodeUnit = codeUnit
        codeUnit = codeUnits.next()
    createFunction(codeUnit.getAddress(),None)

def GetAndDefineTerminatedCStringAt(addr):
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    if cu.getDataType().getName() != "TerminatedCString":
        print("Setting " + str(addr) + " data to TerminatedCString")
        clearListing(cu.getAddress())
        createData(cu.getAddress(),getDataTypes("TerminatedCString")[0])
        cu = currentProgram.getListing().getCodeUnitAt(addr)
    return cu.getValue()

def GetAndDefineFloatAt(addr):
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    if cu.getDataType().getName() != "float":
        print("Setting " + str(addr) + " data to float")
        clearListing(cu.getAddress())
        createData(cu.getAddress(),getDataTypes("float")[0])
        cu = currentProgram.getListing().getCodeUnitAt(addr)
    return cu.getValue()

def FixPCodeAddress(addr):
    return toAddr(addr.toString(False))

def main():
    global pCodeOp
    
    cvars = []
    
    addr_registerCvar = toAddr("RegisterCvar")
    
    listing = currentProgram.getListing()
    references = getReferencesTo(addr_registerCvar)
    iface = decomp.DecompInterface()
    
    for xref in references:
        codeUnits = listing.getCodeUnits(xref.getFromAddress(), False)
        codeUnit = codeUnits.next()
        
        # Check that it's a function CALL
        if codeUnit.getMnemonicString() != "CALL":
            print("Not a function call at " + str(codeUnit.getAddress()) + ". Skipping")
            continue;
        
        print("Function call at " + str(codeUnit.getAddress()))
        
        # Check if call is inside a function
        if getFunctionContaining(codeUnit.getAddress()) is None:
            FindAndCreateFunctionForAddress(codeUnit.getAddress())
            print("Created function")
        
        fn = getFunctionContaining(codeUnit.getAddress())
        
        if fn is None: raise Exception("Function expected at " + str(codeUnit.getAddress()))
        
        iface.openProgram(fn.getProgram())
        decompilation = iface.decompileFunction(fn,0,monitor)
        
        if not decompilation.decompileCompleted(): raise Exception("Decompilation failed for function at " + str(fn.getAddress()) + ". Error: " + decompilation.getErrorMessage())
        
        hf = decompilation.getHighFunction()
        pCodeOps = hf.getPcodeOps()
        
        for pCodeOp in pCodeOps:
            # Search for the right function call
            if pCodeOp.getMnemonic() != "CALL": continue
            pcCall = pCodeOp.getInput(0)
            if not pcCall.isAddress() or pcCall.getAddress() != addr_registerCvar: continue
            
            entry = CvarEntry()
            
            pcVariable = pCodeOp.getInput(1)
            if not pcVariable.isUnique(): raise Exception("Expected 'unique' for input 1")
            
            # Cvar name
            pcName = pCodeOp.getInput(2)
            if not pcName.isUnique(): raise Exception("Expected 'unique' for input 2")
            pcd = pcName.getDef()
            if not pcd.getInput(0).isConstant(): raise Exception("Expected 'constant' for name input")
            entry["name"] = GetAndDefineTerminatedCStringAt(FixPCodeAddress(pcd.getInput(0).getAddress()))
            print(" Name: " + entry["name"])
            
            # Cvar default value
            pcDefaultValue = pCodeOp.getInput(3)
            if not pcDefaultValue.isUnique(): raise Exception("Expected 'unique' for default value input")
            pcd = pcDefaultValue.getDef()
            if not pcd.getInput(0).isConstant(): raise Exception("Expected 'constant' for default value")
            entry["defaultValue"] = GetAndDefineTerminatedCStringAt(FixPCodeAddress(pcd.getInput(0).getAddress()))
            print(" Default value: " + entry["defaultValue"])
            
            # Cvar description
            pcDescription = pCodeOp.getInput(4)
            if not pcDescription.isUnique(): raise Exception("Expected 'unique' for description input")
            pcd = pcDescription.getDef()
            if not pcd.getInput(0).isConstant(): raise Exception("Expected 'constant' for description")
            entry["description"] = GetAndDefineTerminatedCStringAt(FixPCodeAddress(pcd.getInput(0).getAddress()))
            print(" Description: " + entry["description"])
            
            # Cvar flags
            pcFlags = pCodeOp.getInput(5)
            if not pcFlags.isConstant(): raise Exception("Expected 'constant' for flag input")
            entry["flags"] = str(pcFlags.getHigh().getScalar())
            print(" Flags: " + entry["flags"])
            
            # Cvar min
            pcMin = pCodeOp.getInput(6)
            if pcMin.isConstant():
                entry["min"] = pcMin.getHigh().getScalar().getValue()
            elif pcMin.isAddress():
                entry["min"] = GetAndDefineFloatAt(FixPCodeAddress(pcMin.getAddress()))
            else: raise Exception("Unsupported type for min input")
            print(" Min: " + str(entry["min"]))
            
            # Cvar max
            pcMax = pCodeOp.getInput(7)
            if pcMax.isConstant():
                entry["max"] = pcMax.getHigh().getScalar().getValue()
            elif pcMax.isAddress():
                entry["max"] = GetAndDefineFloatAt(FixPCodeAddress(pcMax.getAddress()))
            else: raise Exception("Unsupported type for max input")
            print(" Max: " + str(entry["max"]))
            
            # Check if cvar is already in the list
            existingEntry = [x for x in cvars if x["name"] == entry["name"]]
            
            if bool(existingEntry):
                cvars.remove(existingEntry[0])
            
            cvars.append(entry)
            break
    
    cvars.sort(key=SortByName)
    
    print("dump")
    print(json.dumps(cvars))

main()