/*
This script will compare 2 json data generated from FixAndGetAllCvars.py ghidra script.
It will output all the changes from version_a.txt to version_b.txt

Place older version in version_a.txt file
Place newer version in version_b.txt file
*/

using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace Playground
{
    class Program
    {
        class CvarEntry
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string DefaultValue { get; set; }
            public string Flags { get; set; }

            public float Min { get; set; }
            public float Max { get; set; }
        }

        static async Task Main(string[] args)
        {
            var options = new JsonSerializerOptions()
            {
                PropertyNameCaseInsensitive = true
            };
            var versionA = JsonSerializer.Deserialize<CvarEntry[]>(File.ReadAllText("version_a.txt"),options);
            var versionB = JsonSerializer.Deserialize<CvarEntry[]>(File.ReadAllText("version_b.txt"),options);

            foreach(var cvar in versionB)
            {
                var oldCvar = versionA.FirstOrDefault(c => c.Name.Equals(cvar.Name, StringComparison.OrdinalIgnoreCase));
                if (oldCvar == null)
                {
                    Console.WriteLine($"New cvar: {cvar.Name}");
                }
                else
                {
                    if (!cvar.Description.Equals(oldCvar.Description, StringComparison.OrdinalIgnoreCase))
                        Console.WriteLine($"New description for cvar: {cvar.Name} | {oldCvar.Description} -> {cvar.Description}");

                    if(!cvar.Flags.Equals(oldCvar.Flags))
                        Console.WriteLine($"New flag for cvar: {cvar.Name} | {oldCvar.Flags} -> {cvar.Flags}");

                    if(!cvar.DefaultValue.Equals(oldCvar.DefaultValue))
                        Console.WriteLine($"New default value for cvar: {cvar.Name} | {oldCvar.DefaultValue} -> {cvar.DefaultValue}");
                    
                    if(!cvar.Min.Equals(oldCvar.Min))
                        Console.WriteLine($"New min value for cvar: {cvar.Name} | {oldCvar.Min} -> {cvar.Min}");

                    if (!cvar.Max.Equals(oldCvar.Max))
                        Console.WriteLine($"New max value for cvar: {cvar.Name} | {oldCvar.Max} -> {cvar.Max}");
                }

            }

            foreach(var cvar in versionA)
            {
                if (!versionB.Any(c => c.Name.Equals(cvar.Name, StringComparison.OrdinalIgnoreCase)))
                    Console.WriteLine($"Removed cvar: {cvar.Name}");
            }
        }
    }
}
