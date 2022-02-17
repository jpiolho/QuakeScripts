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

def main():
    global cu
    global cuCvarFlags
    
    cvars = []
    
    listing = currentProgram.getListing()
    references = getReferencesTo(toAddr("RegisterCvar"))
    
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
        
        entry = CvarEntry()
        
        # Get cvar variable
        cuCvarVariable = codeUnits.next() # Cvar variable
        if cuCvarVariable.getMnemonicString() != "LEA" or cuCvarVariable.getRegister(0).getName() != "RCX":
            raise Exception("Unexpected instruction at " + str(cuCvarVariable.getAddress()) + ". Expected LEA RCX")
        
        # Get cvar name
        cuCvarName = codeUnits.next()
        if cuCvarName.getMnemonicString() != "LEA" or cuCvarName.getRegister(0).getName() != "RDX":
            raise Exception("Unexpected instruction at " + str(cuCvarName.getAddress()) + ". Expected LEA RCX")
        cu = listing.getCodeUnitAt(cuCvarName.getAddress(1))
        if cu.getDataType().getName() != "string" and cu.getDataType().getName() != "TerminatedCString":
            # Set the datatype to string
            print("Cvar (" + str(codeUnit.getAddress()) + ") name: Setting datatype at " + str(cu.getAddress()) + " to TerminatedCString")
            createData(cu.getAddress(),getDataTypes("TerminatedCString")[0])
            cu = listing.getCodeUnitAt(cu.getAddress())
        entry["name"] = cu.getValue()
        print(" Name: " + entry["name"])
        
        # Get cvar default value
        cuCvarDefaultValue = codeUnits.next()
        if cuCvarDefaultValue.getMnemonicString() != "LEA" or cuCvarDefaultValue.getRegister(0).getName() != "R8":
            raise Exception("Unexpected instruction at " + str(cuCvarDefaultValue.getAddress()) + ". Expected LEA R8")
        cu = listing.getCodeUnitAt(cuCvarDefaultValue.getAddress(1))
        if cu.getDataType().getName() != "string" and cu.getDataType().getName() != "TerminatedCString":
            # Set the datatype to string
            print("Cvar (" + str(codeUnit.getAddress()) + ") default value: Setting datatype at " + str(cu.getAddress()) + " to TerminatedCString")
            createData(cu.getAddress(),getDataTypes("TerminatedCString")[0])
            cu = listing.getCodeUnitAt(cu.getAddress())
        entry["defaultValue"] = cu.getValue()
        print(" Default value: " + entry["defaultValue"])
        
        # Get cvar description
        cuCvarDescription = codeUnits.next()
        if cuCvarDescription.getMnemonicString() != "LEA" or cuCvarDescription.getRegister(0).getName() != "R9":
            raise Exception("Unexpected instruction at " + str(cuCvarDescription.getAddress()) + ". Expected LEA R9")
        cu = listing.getCodeUnitAt(cuCvarDescription.getAddress(1))
        if cu.getDataType().getName() != "string" and cu.getDataType().getName() != "TerminatedCString":
            # Set the datatype to string
            print("Cvar (" + str(codeUnit.getAddress()) + ") default value: Setting datatype at " + str(cu.getAddress()) + " to TerminatedCString")
            createData(cu.getAddress(),getDataTypes("TerminatedCString")[0])
            cu = listing.getCodeUnitAt(cu.getAddress())
        entry["description"] = cu.getValue()
        print(" Description: " + entry["description"])
        
        # Get cvar flags
        cuCvarFlags = codeUnits.next()
        if cuCvarFlags.getMnemonicString() != "MOV":
            raise Exception("Unexpected instruction at " + str(cuCvarFlags.getAddress()) + ". Expected MOV")
        entry["flags"] = str(cuCvarFlags.getScalar(1))
        
        cu = codeUnits.next()
        if cu.getMnemonicString() != "MOVSS" or cu.getRegister(1).getName() != "XMM1":
            raise Exception("Unexpected instruction at " + str(cu.getAddress()) + ". Expected MOVSS XMM1")
            
        # Get cvar minimum value
        cuCvarMinValue = codeUnits.next()
        if cuCvarMinValue.getMnemonicString() == "XORPS" and cuCvarMinValue.getRegister(0).getName() == "XMM1":
            entry["min"] = 0.0;
        elif cuCvarMinValue.getMnemonicString() == "MOVSS" and cuCvarMinValue.getRegister(0).getName() == "XMM1":
            cu = listing.getCodeUnitAt(cuCvarMinValue.getAddress(1))
            if cu.getDataType().getName() != "float":
                print("Cvar (" + str(codeUnit.getAddress()) + ") min: Setting datatype at " + str(cu.getAddress()) + " to Float")
                clearListing(cu.getAddress())
                createData(cu.getAddress(),getDataTypes("Float")[0])
                cu = listing.getCodeUnitAt(cu.getAddress())
            entry["min"] = cu.getValue()
        else:
            raise Exception("Unexpected instruction at " + str(cu.getAddress()) + ". Expected MOVSS XMM1 or XORPS XMM1")
        print(" Min: " + str(entry["min"]))
        
        
        cu = codeUnits.next()
        if cu.getMnemonicString() != "MOVSS" or cu.getRegister(1).getName() != "XMM0":
            raise Exception("Unexpected instruction at " + str(cu.getAddress()) + ". Expected MOVSS XMM0")
            
        # Get cvar minimum value
        cuCvarMaxValue = codeUnits.next()
        if cuCvarMaxValue.getMnemonicString() == "XORPS" and cuCvarMaxValue.getRegister(0).getName() == "XMM0":
            entry["max"] = 0.0;
        elif cuCvarMaxValue.getMnemonicString() == "MOVSS" and cuCvarMaxValue.getRegister(0).getName() == "XMM0":
            cu = listing.getCodeUnitAt(cuCvarMaxValue.getAddress(1))
            if cu.getDataType().getName() != "float":
                print("Cvar (" + str(codeUnit.getAddress()) + ") max: Setting datatype at " + str(cu.getAddress()) + " to Float")
                clearListing(cu.getAddress())
                createData(cu.getAddress(),getDataTypes("float")[0])
                cu = listing.getCodeUnitAt(cu.getAddress())
            entry["max"] = cu.getValue()
        else:
            raise Exception("Unexpected instruction at " + str(cu.getAddress()) + ". Expected MOVSS XMM0 or XORPS XMM0")
        print(" Max: " + str(entry["max"]))
        
        
        # Check if cvar is already in the list
        existingEntry = [x for x in cvars if x["name"] == entry["name"]]
        
        if bool(existingEntry):
            cvars.remove(existingEntry[0])
        
        cvars.append(entry)
    
    cvars.sort(key=SortByName)
    
    print("dump")
    print(json.dumps(cvars))

main()