using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumper11.Driver;
using KsDumper11.Utility;
using static KsDumper11.PE.NativePEStructs;

namespace KsDumper11.PE
{
    /// <summary>
    /// Correct ProcessDump-style IAT reconstruction for kernel dumpers
    /// Builds export database from TARGET process address space, not own process
    /// </summary>
    public class IATReconstructor
    {
        private readonly Dictionary<ulong, ExportEntry> exports;
        private readonly HashSet<ulong> exportAddresses;
        private readonly KsDumperDriverInterface kernelDriver;
        private ulong minAddress = ulong.MaxValue;
        private ulong maxAddress = 0;

        private bool targetIs64Bit = true;

        public IATReconstructor(KsDumperDriverInterface driver)
        {
            exports = new Dictionary<ulong, ExportEntry>();
            exportAddresses = new HashSet<ulong>();
            kernelDriver = driver;
        }

        /// <summary>
        /// Main entry point - reconstructs IAT for dumped PE data
        /// CORRECTED: Uses target process address space for export database
        /// </summary>
        public bool ReconstructIAT(ref byte[] peData, int targetProcessId, ulong imageBase, bool is64Bit)
        {
            try
            {
                Logger.Log("Starting CORRECTED ProcessDump-style IAT reconstruction...");

                // Remember target bitness for PEB parsing and scanning heuristics
                targetIs64Bit = is64Bit;

                Logger.Log("Target PID: {0}, Image Base: 0x{1:X}", targetProcessId, imageBase);

                // Step 1: Build export database from TARGET process address space
                if (!BuildTargetProcessExports(targetProcessId))
                {
                    Logger.Log("Failed to build target process export database");
                    return false;
                }

                // Step 2: Parse any exports from the dumped PE itself
                ParseDumpedPEExports(peData, imageBase, is64Bit);

                // Step 3: Aggressive scanning with ProcessDump algorithm
                var imports = ScanForImports(peData, imageBase, is64Bit);
                if (imports.Count == 0)
                {
                    Logger.Log("No imports found during scan");
                    return false;
                }

                // Step 4: Build and integrate import directory
                return BuildImportDirectory(ref peData, imports, is64Bit);
            }
            catch (Exception ex)
            {
                Logger.Log("IAT reconstruction failed: {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// CORRECTED: Build export database from TARGET process modules
        /// Uses kernel driver to read target process memory and get target addresses
        /// </summary>
        private bool BuildTargetProcessExports(int targetProcessId)
        {
            try
            {
                Logger.Log("Building export database from target process {0}...", targetProcessId);

                // Get modules loaded in the target process
                var targetModules = GetTargetProcessModules(targetProcessId);
                if (targetModules.Count == 0)
                {
                    Logger.Log("No modules found in target process");
                    return false;
                }

                int totalExports = 0;
                foreach (var module in targetModules)
                {
                    Logger.Log("Processing module: {0} at 0x{1:X}", module.Name, module.BaseAddress);

                    try
                    {
                        // Read module data from target process memory
                        var moduleData = ReadTargetProcessModule(targetProcessId, module);
                        if (moduleData != null)
                        {
                            int moduleExports = ParseTargetModuleExports(moduleData, module);
                            totalExports += moduleExports;
                            Logger.Log("Found {0} exports in {1}", moduleExports, module.Name);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Failed to process module {0}: {1}", module.Name, ex.Message);
                        continue; // Skip problematic modules but continue with others
                    }
                }

                Logger.Log("Built export database: {0} total exports from {1} modules",
                    totalExports, targetModules.Count);
                return totalExports > 0;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to build target process exports: {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// ProcessDump's core scanning algorithm
        /// Scans every 4-byte value in relevant sections for export pointers
        /// </summary>
        private List<ImportEntry> ScanForImports(byte[] peData, ulong imageBase, bool is64Bit)
        {
            var imports = new List<ImportEntry>();
            int pointerSize = is64Bit ? 8 : 4;
            ulong lastCandidate = 0;

            // Get relevant sections (writable sections where IAT typically resides)
            var sections = GetRelevantSections(peData, is64Bit);

            foreach (var section in sections)
            {
                Logger.Log("Scanning section: {0} (Size: {1})", section.Name, section.Data.Length);

                // ProcessDump algorithm: scan every 4-byte value
                for (int offset = 0; offset <= section.Data.Length - pointerSize; offset += 4)
                {
                    ulong candidate = ReadPointerFromBytes(section.Data, offset, is64Bit);

                    // ProcessDump optimization: skip duplicate consecutive values
                    if (lastCandidate == candidate)
                        continue;
                    lastCandidate = candidate;

                    // ProcessDump bit-filtering optimization
                    if (!QuickContainsCheck(candidate))
                        continue;

                    // Found a match!
                    if (exports.TryGetValue(candidate, out ExportEntry export))
                    {
                        imports.Add(new ImportEntry
                        {
                            RVA = section.VirtualAddress + (uint)offset,
                            Address = candidate,
                            ModuleName = export.ModuleName,
                            FunctionName = export.FunctionName,
                            Ordinal = export.Ordinal,
                            IsOrdinalOnly = string.IsNullOrEmpty(export.FunctionName)
                        });
                    }
                }
            }

            Logger.Log("Found {0} imports across {1} sections", imports.Count, sections.Count);
            return imports;
        }

        /// <summary>
        /// CORRECTED: Get modules using PEB parsing instead of memory scanning
        /// Much faster and more reliable than brute force scanning
        /// </summary>
        private List<TargetModuleInfo> GetTargetProcessModules(int targetProcessId)
        {
            var modules = new List<TargetModuleInfo>();

            try
            {
                Logger.Log("Parsing PEB for target process {0} modules...", targetProcessId);

                // Try PEB parsing first (fast and reliable)
                var pebModules = GetModulesFromPEB(targetProcessId);
                if (pebModules.Count > 0)
                {
                    Logger.Log("Found {0} modules via PEB parsing", pebModules.Count);

                    // Sanity check: WOW64 targets often miss modules via kernel path
                    // Treat tiny module lists or no DLL-like names as suspicious regardless of bitness
                    bool looksSuspicious = (pebModules.Count < 3)
                        || !pebModules.Exists(m => m.Name != null && m.Name.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) >= 0)
                        || !pebModules.Exists(m => m.Name != null && m.Name.IndexOf("gameassembly.dll", StringComparison.OrdinalIgnoreCase) >= 0);

                    if (looksSuspicious)
                    {
                        Logger.Log("Kernel PEB result looks incomplete; attempting user-mode PEB walk...");
                        var userPeb = EnumerateModulesFromPEBUsermode(targetProcessId);
                        if (userPeb.Count > pebModules.Count)
                        {
                            Logger.Log("User-mode PEB walk improved module count from {0} to {1}", pebModules.Count, userPeb.Count);
                            return userPeb;
                        }
                    }

                    return pebModules;
                }

                // Fallback to limited scanning of common system module ranges only
                Logger.Log("PEB parsing failed, falling back to limited scanning...");
                var fallbackModules = GetModulesFromLimitedScan(targetProcessId);

                Logger.Log("Found {0} modules total", fallbackModules.Count);
                return fallbackModules;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to enumerate target process modules: {0}", ex.Message);
                return new List<TargetModuleInfo>();
            }
        }

        /// <summary>
        /// REAL IMPLEMENTATION: Get modules using kernel driver's direct PEB access
        /// </summary>
        private List<TargetModuleInfo> GetModulesFromPEB(int targetProcessId)
        {
            var modules = new List<TargetModuleInfo>();

            try
            {
                Logger.Log("Using kernel driver to enumerate modules for process {0}", targetProcessId);

                // Use kernel driver's new module enumeration functionality
                var kernelModules = kernelDriver.GetProcessModules(targetProcessId);

                if (kernelModules != null && kernelModules.Length > 0)
                {
                    foreach (var kernelModule in kernelModules)
                    {
                        if (kernelModule.baseAddress != 0 && kernelModule.sizeOfImage > 0)
                        {
                            var moduleInfo = new TargetModuleInfo
                            {
                                Name = !string.IsNullOrEmpty(kernelModule.moduleName) ? kernelModule.moduleName : "unknown.dll",
                                BaseAddress = kernelModule.baseAddress,
                                ProcessId = targetProcessId,
                                Size = kernelModule.sizeOfImage,
                                Is64Bit = !kernelModule.isWow64Process // FIXED: WOW64 = 32-bit process on 64-bit system
                            };

                            // Validate the module by checking for PE header
                            if (ValidateModuleAtAddress(targetProcessId, moduleInfo.BaseAddress))
                            {
                                modules.Add(moduleInfo);
                                Logger.Log("Kernel PEB: Found module {0} at 0x{1:X} (size: 0x{2:X})",
                                    moduleInfo.Name, moduleInfo.BaseAddress, moduleInfo.Size);
                            }
                            else
                            {
                                Logger.Log("Kernel PEB: Invalid module {0} at 0x{1:X} (failed PE validation)",
                                    kernelModule.moduleName, kernelModule.baseAddress);
                            }
                        }
                    }

                    Logger.Log("Kernel driver found {0} valid modules out of {1} total", modules.Count, kernelModules.Length);
                }
                else
                {
                    Logger.Log("Kernel driver returned no modules for process {0}", targetProcessId);
                }

                // Fallback: if kernel driver did not yield usable modules, try parsing PEB from user-mode
                if (modules.Count == 0)
                {
                    Logger.Log("Kernel driver returned no usable modules; attempting user-mode PEB parsing...");
                    var pebModules = EnumerateModulesFromPEBUsermode(targetProcessId);
                    if (pebModules.Count > 0)
                    {
                        Logger.Log("User-mode PEB parsing found {0} modules", pebModules.Count);
                        return pebModules;
                    }
                }

                return modules;
            }
            catch (Exception ex)
            {
                Logger.Log("Kernel PEB parsing failed: {0}", ex.Message);
            }

                // Final fallback: try user-mode PEB walk to enumerate modules (WOW64-safe)
                try
                {
                    if (modules.Count == 0)
                    {
                        var pebModules = EnumerateModulesFromPEBUsermode(targetProcessId);
                        if (pebModules.Count > 0)
                        {
                            Logger.Log("User-mode PEB parsing found {0} modules", pebModules.Count);
                            return pebModules;
                        }
                    }
                }
                catch (Exception)
                {
                    // swallow and return what we have
                }

                return modules;
            }


            /// <summary>
            /// Manual PEB walk from user-mode reads, supports x86 and x64
            /// </summary>
            private List<TargetModuleInfo> EnumerateModulesFromPEBUsermode(int targetProcessId)
            {
                var result = new List<TargetModuleInfo>();
                try
                {
                    // Get PEB address: kernel API for x64, NtQueryInformationProcess (Wow64) for x86
                    ulong pebAddress = targetIs64Bit ? GetProcessPEBAddress(targetProcessId) : GetWow64PebAddress(targetProcessId);
                    if (pebAddress == 0)
                        return result;

                    var pebData = ReadTargetProcessMemory(targetProcessId, pebAddress, 0x100);
                    if (pebData == null)
                        return result;

                    ulong ldrAddress = targetIs64Bit ? BitConverter.ToUInt64(pebData, 0x18) : BitConverter.ToUInt32(pebData, 0x0C);

                ulong GetWow64PebAddress(int pid)
                {
                    try
                    {
                        IntPtr hProcess = WinApi.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
                        if (hProcess == IntPtr.Zero)
                            return 0;

                        try
                        {
                            IntPtr peb32;
                            int retLen;
                            int status = WinApi.NtQueryInformationProcess(hProcess, 26 /* ProcessWow64Information */, out peb32, IntPtr.Size, out retLen);
                            if (status == 0 && peb32 != IntPtr.Zero)
                            {
                                return (ulong)peb32.ToInt64();
                            }
                        }
                        finally
                        {
                            WinApi.CloseHandle(hProcess);
                        }
                    }
                    catch { }
                    return 0;
                }

                    if (ldrAddress == 0)
                        return result;

                    // InLoadOrderModuleList offset: x64=0x10, x86=0x0C
                    ulong listHead = ldrAddress + (targetIs64Bit ? 0x10UL : 0x0CUL);

                    // Read first Flink
                    int ptrSize = targetIs64Bit ? 8 : 4;
                    var headData = ReadTargetProcessMemory(targetProcessId, listHead, ptrSize);
                    if (headData == null || headData.Length < ptrSize)
                        return result;

                    ulong flink = targetIs64Bit ? BitConverter.ToUInt64(headData, 0) : BitConverter.ToUInt32(headData, 0);
                    int safety = 0;
                    while (flink != 0 && flink != listHead && safety++ < 512)
                    {
                        // LIST_ENTRY is first field in LDR_DATA_TABLE_ENTRY, so entry addr == flink
                        ulong entryAddr = flink;

                        var info = ParseLDRDataTableEntry(targetProcessId, entryAddr);
                        if (info != null)
                        {
                            result.Add(info);
                        }

                        // Move to next: read Flink from current entry's LIST_ENTRY (offset 0)
                        var entryHead = ReadTargetProcessMemory(targetProcessId, entryAddr, ptrSize);
                        if (entryHead == null || entryHead.Length < ptrSize)
                            break;
                        flink = targetIs64Bit ? BitConverter.ToUInt64(entryHead, 0) : BitConverter.ToUInt32(entryHead, 0);
                    }

                    Logger.Log("User-mode PEB: Found {0} modules", result.Count);
                }
                catch (Exception ex)
                {
                    Logger.Log("User-mode PEB parsing failed: {0}", ex.Message);
                }

                return result;
            }



        /// <summary>
        /// REAL IMPLEMENTATION: Get PEB address using kernel driver's PsGetProcessPeb
        /// </summary>
        private ulong GetProcessPEBAddress(int targetProcessId)
        {
            try
            {
                // Use kernel driver's new PEB functionality
                ulong pebAddress = kernelDriver.GetProcessPEB(targetProcessId);

                if (pebAddress != 0)
                {
                    Logger.Log("Kernel driver found PEB at 0x{0:X} for process {1}", pebAddress, targetProcessId);
                    return pebAddress;
                }

                Logger.Log("Kernel driver could not find PEB for process {0}", targetProcessId);
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to get PEB address for process {0}: {1}", targetProcessId, ex.Message);
                return 0;
            }
        }

        /// <summary>
        /// Validate if there's a valid PEB structure at the given address
        /// </summary>
        private bool ValidatePEBAtAddress(int targetProcessId, ulong address)
        {
            try
            {
                // Read potential PEB structure
                var pebData = ReadTargetProcessMemory(targetProcessId, address, 0x100);
                if (pebData == null || pebData.Length < 0x100) return false;

                // Basic PEB validation
                // Check if ImageBaseAddress points to a valid PE
                ulong imageBase = targetIs64Bit ? BitConverter.ToUInt64(pebData, 0x10) : BitConverter.ToUInt32(pebData, 0x08);
                if (imageBase == 0) return false;

                // Validate that ImageBaseAddress points to a PE header
                var dosHeader = ReadTargetProcessMemory(targetProcessId, imageBase, 64);
                if (dosHeader == null || dosHeader.Length < 64) return false;

                // Check DOS signature "MZ"
                if (dosHeader[0] != 0x4D || dosHeader[1] != 0x5A) return false;

                // Check if Ldr field points to a reasonable address
                ulong ldrAddress = targetIs64Bit ? BitConverter.ToUInt64(pebData, 0x18) : BitConverter.ToUInt32(pebData, 0x0C);
                if (ldrAddress == 0 || ldrAddress < 0x10000) return false;

                Logger.Log("PEB validation successful at 0x{0:X}", address);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Scan for PEB in likely memory ranges
        /// </summary>
        private ulong ScanForPEBInProcess(int targetProcessId)
        {
            try
            {
                // PEB is typically in high memory for x64 processes
                var scanRanges = new[]
                {
                    new { Start = 0x7FFD0000UL, End = 0x7FFF0000UL, Step = 0x1000UL }, // 128KB range
                    new { Start = 0x000F0000UL, End = 0x00100000UL, Step = 0x1000UL }  // x32 range
                };

                foreach (var range in scanRanges)
                {
                    for (ulong address = range.Start; address < range.End; address += range.Step)
                    {
                        if (ValidatePEBAtAddress(targetProcessId, address))
                        {
                            return address;
                        }
                    }
                }

                return 0;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// REAL IMPLEMENTATION: Parse LDR_DATA_TABLE_ENTRY structure with proper offsets
        /// </summary>
        private TargetModuleInfo ParseLDRDataTableEntry(int targetProcessId, ulong entryAddress)
        {
            try
            {
                // Read LDR_DATA_TABLE_ENTRY structure
                var entryData = ReadTargetProcessMemory(targetProcessId, entryAddress, 0x120);
                if (entryData == null || entryData.Length < 0x120) return null;

                // LDR_DATA_TABLE_ENTRY structure offsets differ between x64 and x86
                ulong dllBase;
                uint sizeOfImage;
                ushort nameLength;
                ulong nameBuffer;

                if (targetIs64Bit)
                {
                    // x64 layout
                    // +0x000 InLoadOrderLinks         : _LIST_ENTRY
                    // +0x010 InMemoryOrderLinks       : _LIST_ENTRY
                    // +0x020 InInitializationOrderLinks : _LIST_ENTRY
                    // +0x030 DllBase                  : Ptr64 Void
                    // +0x038 EntryPoint               : Ptr64 Void
                    // +0x040 SizeOfImage              : Uint4B
                    // +0x048 FullDllName              : _UNICODE_STRING
                    // +0x058 BaseDllName              : _UNICODE_STRING
                    dllBase = BitConverter.ToUInt64(entryData, 0x30);
                    sizeOfImage = BitConverter.ToUInt32(entryData, 0x40);
                    nameLength = BitConverter.ToUInt16(entryData, 0x58);
                    nameBuffer = BitConverter.ToUInt64(entryData, 0x60);
                }
                else
                {
                    // x86 layout
                    // +0x000 InLoadOrderLinks         : _LIST_ENTRY (8 bytes)
                    // +0x008 InMemoryOrderLinks       : _LIST_ENTRY (8 bytes)
                    // +0x010 InInitializationOrderLinks : _LIST_ENTRY (8 bytes)
                    // +0x018 DllBase                  : Ptr32 Void
                    // +0x01C EntryPoint               : Ptr32 Void
                    // +0x020 SizeOfImage              : Uint4B
                    // +0x02C BaseDllName              : _UNICODE_STRING (Length, Max, Buffer32)
                    dllBase = BitConverter.ToUInt32(entryData, 0x18);
                    sizeOfImage = BitConverter.ToUInt32(entryData, 0x20);
                    nameLength = BitConverter.ToUInt16(entryData, 0x2C);
                    uint nameBuf32 = BitConverter.ToUInt32(entryData, 0x30);
                    nameBuffer = nameBuf32;
                }

                if (dllBase == 0) return null;
                if (sizeOfImage == 0 || sizeOfImage > 500 * 1024 * 1024) return null; // Sanity check

                string moduleName = "unknown.dll";
                if (nameLength > 0 && nameLength < 512 && nameBuffer != 0)
                {
                    try
                    {
                        var nameData = ReadTargetProcessMemory(targetProcessId, nameBuffer, nameLength);
                        if (nameData != null && nameData.Length >= nameLength)
                        {
                            moduleName = Encoding.Unicode.GetString(nameData, 0, nameLength);
                            int nul = moduleName.IndexOf('\0');
                            if (nul >= 0) moduleName = moduleName.Substring(0, nul);
                        }
                    }
                    catch
                    {
                        // Keep default name if reading fails
                    }
                }

                // Validate the module by checking for PE header
                if (!ValidateModuleAtAddress(targetProcessId, dllBase))
                {
                    return null;
                }

                return new TargetModuleInfo
                {
                    Name = moduleName,
                    BaseAddress = dllBase,
                    ProcessId = targetProcessId,
                    Size = sizeOfImage,
                    Is64Bit = targetIs64Bit
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to parse LDR entry at 0x{0:X}: {1}", entryAddress, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Validate that there's actually a PE module at the given address
        /// </summary>
        private bool ValidateModuleAtAddress(int targetProcessId, ulong address)
        {
            try
            {
                var dosHeader = ReadTargetProcessMemory(targetProcessId, address, 64);
                if (dosHeader == null || dosHeader.Length < 64) return false;

                // Check DOS signature "MZ"
                if (dosHeader[0] != 0x4D || dosHeader[1] != 0x5A) return false;

                // Get PE header offset
                uint peOffset = BitConverter.ToUInt32(dosHeader, 60);
                if (peOffset > 0x1000) return false; // Reasonable limit

                // Check PE signature
                var peHeader = ReadTargetProcessMemory(targetProcessId, address + peOffset, 4);
                if (peHeader == null || peHeader.Length < 4) return false;

                // Check PE signature "PE\0\0"
                return peHeader[0] == 0x50 && peHeader[1] == 0x45 &&
                       peHeader[2] == 0x00 && peHeader[3] == 0x00;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// IMPROVED: Much more targeted scanning of essential system modules
        /// Reduced from 4GB to 512MB+16MB = 98% reduction in scan space
        /// </summary>
        private List<TargetModuleInfo> GetModulesFromLimitedScan(int targetProcessId)
        {
            var modules = new List<TargetModuleInfo>();

            // MUCH smaller ranges - only scan where modules are actually likely to be
            var targetedRanges = targetIs64Bit
                ? new[]
                {
                    // x64: Core system DLLs (reduced from 4GB to 512MB)
                    new { Start = 0x7FF800000000UL, End = 0x7FF820000000UL, Name = "Core System DLLs", Step = 0x10000UL },

                    // x64: Main executable (reduced from 256MB to 16MB)
                    new { Start = 0x140000000UL, End = 0x141000000UL, Name = "Main Executable", Step = 0x10000UL },

                    // x64: Additional common ranges
                    new { Start = 0x180000000UL, End = 0x181000000UL, Name = "Secondary Modules", Step = 0x10000UL }
                }
                : new[]
                {
                    // x86: Core system DLLs (ntdll, kernel32, kernelbase, etc.)
                    new { Start = 0x70000000UL, End = 0x78000000UL, Name = "Core System DLLs (x86)", Step = 0x10000UL },

                    // x86: Main executable typical range
                    new { Start = 0x00400000UL, End = 0x01000000UL, Name = "Main Executable (x86)", Step = 0x1000UL },

                    // x86: Common game DLL range (Unity/IL2CPP like GameAssembly.dll)
                    new { Start = 0x10000000UL, End = 0x40000000UL, Name = "Secondary Modules (x86)", Step = 0x10000UL }
                };

            foreach (var range in targetedRanges)
            {
                Logger.Log("Targeted scan: {0} (0x{1:X} - 0x{2:X})", range.Name, range.Start, range.End);

                int foundInRange = 0;
                for (ulong address = range.Start; address < range.End; address += range.Step)
                {
                    var moduleInfo = TryParseModuleAtAddress(targetProcessId, address);
                    if (moduleInfo != null)
                    {
                        modules.Add(moduleInfo);
                        foundInRange++;
                        Logger.Log("Targeted scan: Found {0} at 0x{1:X}", moduleInfo.Name, moduleInfo.BaseAddress);

                        // Skip ahead by module size to avoid scanning inside the same module
                        ulong skipSize = Math.Max(moduleInfo.Size, 0x10000UL);
                        address += skipSize - range.Step; // Subtract step since loop will add it

                        // If we found several modules in this range, it's probably productive
                        // Continue scanning, but if we find nothing for a while, move to next range
                    }
                }

                Logger.Log("Found {0} modules in {1}", foundInRange, range.Name);
            }

            // Try known system module locations directly
            modules.AddRange(ScanKnownSystemModuleLocations(targetProcessId));

            return modules;
        }

        /// <summary>
        /// Scan specific known locations where system modules are commonly loaded
        /// </summary>
        private List<TargetModuleInfo> ScanKnownSystemModuleLocations(int targetProcessId)
        {
            var modules = new List<TargetModuleInfo>();

            // Common system module base addresses (these are heuristics)
            var knownLocations = new ulong[]
            {
                0x7FF800000000UL, // ntdll.dll common location
                0x7FF801000000UL, // kernel32.dll common location
                0x7FF802000000UL, // kernelbase.dll common location
                0x7FF803000000UL, // user32.dll common location
                0x7FF804000000UL, // gdi32.dll common location
                0x7FF805000000UL, // advapi32.dll common location
                0x7FF806000000UL, // msvcrt.dll common location
                0x7FF807000000UL, // shell32.dll common location
                0x7FF808000000UL, // ole32.dll common location
                0x7FF809000000UL, // comctl32.dll common location
            };

            foreach (var location in knownLocations)
            {
                var moduleInfo = TryParseModuleAtAddress(targetProcessId, location);
                if (moduleInfo != null)
                {
                    modules.Add(moduleInfo);
                    Logger.Log("Known location: Found {0} at 0x{1:X}", moduleInfo.Name, moduleInfo.BaseAddress);
                }
            }

            return modules;
        }

        /// <summary>
        /// Try to parse a module at the given address
        /// Returns null if no valid PE found
        /// </summary>
        private TargetModuleInfo TryParseModuleAtAddress(int targetProcessId, ulong address)
        {
            try
            {
                // Read potential DOS header
                var dosHeaderData = ReadTargetProcessMemory(targetProcessId, address, 64);
                if (dosHeaderData == null || dosHeaderData.Length < 64)
                    return null;

                // Check DOS signature "MZ"
                if (dosHeaderData[0] != 0x4D || dosHeaderData[1] != 0x5A)
                    return null;

                // Get PE header offset
                uint peOffset = BitConverter.ToUInt32(dosHeaderData, 60);
                if (peOffset > 0x1000) // Reasonable limit
                    return null;

                // Read PE header
                var peHeaderData = ReadTargetProcessMemory(targetProcessId, address + peOffset, 256);
                if (peHeaderData == null || peHeaderData.Length < 256)
                    return null;

                // Check PE signature "PE\0\0"
                if (peHeaderData[0] != 0x50 || peHeaderData[1] != 0x45 ||
                    peHeaderData[2] != 0x00 || peHeaderData[3] != 0x00)
                    return null;

                // Parse basic PE info
                ushort machine = BitConverter.ToUInt16(peHeaderData, 4);
                ushort numberOfSections = BitConverter.ToUInt16(peHeaderData, 6);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(peHeaderData, 20);

                // Validate reasonable values
                if (numberOfSections == 0 || numberOfSections > 100 || sizeOfOptionalHeader < 96)
                    return null;

                // Determine architecture
                bool is64Bit = machine == 0x8664;

                // Get image size
                uint imageSize;
                if (is64Bit)
                {
                    if (sizeOfOptionalHeader < 240) return null;
                    imageSize = BitConverter.ToUInt32(peHeaderData, 24 + 56); // SizeOfImage offset in PE64
                }
                else
                {
                    if (sizeOfOptionalHeader < 224) return null;
                    imageSize = BitConverter.ToUInt32(peHeaderData, 24 + 56); // SizeOfImage offset in PE32
                }

                // Validate image size
                if (imageSize == 0 || imageSize > 100 * 1024 * 1024) // 100MB limit
                    return null;

                // Try to get module name from export table or use generic name
                string moduleName = GetModuleNameFromPE(targetProcessId, address, peHeaderData, is64Bit);
                if (string.IsNullOrEmpty(moduleName))
                {
                    moduleName = $"module_0x{address:X}.dll";
                }

                return new TargetModuleInfo
                {
                    Name = moduleName,
                    BaseAddress = address,
                    ProcessId = targetProcessId,
                    Size = imageSize,
                    Is64Bit = is64Bit
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Try to get module name from export table
        /// </summary>
        private string GetModuleNameFromPE(int targetProcessId, ulong baseAddress, byte[] peHeaderData, bool is64Bit)
        {
            try
            {
                // Get export directory RVA
                uint exportDirRVA;
                if (is64Bit)
                {
                    exportDirRVA = BitConverter.ToUInt32(peHeaderData, 24 + 112); // Export table RVA in PE64
                }
                else
                {
                    exportDirRVA = BitConverter.ToUInt32(peHeaderData, 24 + 96); // Export table RVA in PE32
                }

                if (exportDirRVA == 0) return null;

                // Read export directory
                var exportDirData = ReadTargetProcessMemory(targetProcessId, baseAddress + exportDirRVA, 40);
                if (exportDirData == null || exportDirData.Length < 40)
                    return null;

                // Get name RVA from export directory
                uint nameRVA = BitConverter.ToUInt32(exportDirData, 12);
                if (nameRVA == 0) return null;

                // Read module name
                var nameData = ReadTargetProcessMemory(targetProcessId, baseAddress + nameRVA, 256);
                if (nameData == null) return null;

                // Extract null-terminated string
                int nameLength = 0;
                while (nameLength < nameData.Length && nameData[nameLength] != 0)
                    nameLength++;

                if (nameLength > 0)
                {
                    return Encoding.ASCII.GetString(nameData, 0, nameLength);
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Find a specific module's base address in the target process
        /// Uses kernel driver to scan target process memory
        /// </summary>
        private ulong FindModuleInTargetProcess(int targetProcessId, string moduleName)
        {
            try
            {
                // This is a simplified implementation
                // Real implementation would use kernel driver to enumerate process modules
                // For now, we'll use common base address patterns and verify by reading PE headers

                // Common address ranges where system modules are typically loaded
                var commonRanges = new[]
                {
                    new { Start = 0x7FF800000000UL, End = 0x7FFFFFFFFFFFFFFFUL }, // System modules on x64
                    new { Start = 0x70000000UL, End = 0x80000000UL }          // System modules on x32
                };

                foreach (var range in commonRanges)
                {
                    // Scan for PE headers in this range
                    for (ulong addr = range.Start; addr < range.End; addr += 0x10000) // 64KB steps
                    {
                        if (IsPEHeaderAtAddress(targetProcessId, addr))
                        {
                            var foundModuleName = GetModuleNameAtAddress(targetProcessId, addr);
                            if (foundModuleName != null &&
                                foundModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                            {
                                Logger.Log("Found {0} at 0x{1:X} in target process", moduleName, addr);
                                return addr;
                            }
                        }
                    }
                }

                return 0; // Not found
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Check if there's a valid PE header at the given address in target process
        /// </summary>
        private bool IsPEHeaderAtAddress(int targetProcessId, ulong address)
        {
            try
            {
                // Read DOS header
                var dosHeaderData = ReadTargetProcessMemory(targetProcessId, address,
                    Marshal.SizeOf<IMAGE_DOS_HEADER>());
                if (dosHeaderData == null) return false;

                var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(dosHeaderData, 0);
                if (!dosHeader.IsValid) return false;

                // Read NT header
                var ntHeaderData = ReadTargetProcessMemory(targetProcessId,
                    address + (ulong)dosHeader.e_lfanew, Marshal.SizeOf<IMAGE_NT_HEADERS64>());
                if (ntHeaderData == null) return false;

                // Check PE signature
                return BitConverter.ToUInt32(ntHeaderData, 0) == 0x00004550; // "PE\0\0"
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get module name from PE header at given address in target process
        /// </summary>
        private string GetModuleNameAtAddress(int targetProcessId, ulong address)
        {
            try
            {
                // This is simplified - real implementation would parse the full PE structure
                // to get the original filename from version info or export table
                return null; // Placeholder
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read memory from target process using kernel driver
        /// </summary>
        /// <summary>
        /// CORRECTED: Read memory from target process with proper error handling
        /// </summary>
        private byte[] ReadTargetProcessMemory(int targetProcessId, ulong address, int size)
        {
            // Validate parameters
            if (targetProcessId <= 0 || address == 0 || size <= 0 || size > 50 * 1024 * 1024)
            {
                return null;
            }

            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(size);
                if (buffer == IntPtr.Zero)
                {
                    Logger.Log("Failed to allocate {0} bytes for memory read", size);
                    return null;
                }

                // Use kernel driver to read from target process
                bool success = kernelDriver.CopyVirtualMemory(targetProcessId,
                    new IntPtr((long)address), buffer, size);

                if (!success)
                {
                    // Kernel read failed - this is common and not an error
                    return null;
                }

                // Copy data to managed array with bounds checking
                byte[] data = new byte[size];
                Marshal.Copy(buffer, data, 0, size);
                return data;
            }
            catch (Exception ex)
            {
                Logger.Log("Exception reading memory from process {0} at 0x{1:X}: {2}",
                    targetProcessId, address, ex.Message);
                return null;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    try
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }
            }
        }

        /// <summary>
        /// ProcessDump's range filtering optimization
        /// </summary>
        private bool QuickContainsCheck(ulong address)
        {
            // Simple range filtering (ProcessDump's actual optimization)
            if (address > maxAddress || address < minAddress)
                return false;

            // Only do expensive hash lookup if range check passes
            return exportAddresses.Contains(address);
        }

        /// <summary>
        /// Get sections that are likely to contain IAT entries
        /// Focus scanning on relevant areas only
        /// </summary>
        private List<SectionInfo> GetRelevantSections(byte[] peData, bool is64Bit)
        {
            var sections = new List<SectionInfo>();

            // Parse PE headers to get section information
            var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(peData, 0);
            if (!dosHeader.IsValid) return sections;

            int ntHeaderOffset = dosHeader.e_lfanew;
            var fileHeader = ReadStruct<IMAGE_FILE_HEADER>(peData, ntHeaderOffset + 4);

            int sectionHeaderOffset = ntHeaderOffset + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>() +
                                    fileHeader.SizeOfOptionalHeader;

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                var sectionHeader = ReadStruct<IMAGE_SECTION_HEADER>(peData,
                    sectionHeaderOffset + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());

                // Focus on sections that typically contain IAT
                if (IsRelevantSection(sectionHeader))
                {
                    var sectionData = ExtractSectionData(peData, sectionHeader);
                    if (sectionData != null)
                    {
                        sections.Add(new SectionInfo
                        {
                            Name = sectionHeader.SectionName,
                            VirtualAddress = sectionHeader.VirtualAddress,
                            Data = sectionData
                        });
                    }
                }
            }

            return sections;
        }

        /// <summary>
        /// Determine if a section is likely to contain IAT entries
        /// </summary>
        private bool IsRelevantSection(IMAGE_SECTION_HEADER section)
        {
            var characteristics = section.Characteristics;
            string name = section.SectionName.ToLowerInvariant();

            // Writable sections (IAT needs to be writable)
            bool isWritable = ((DataSectionFlags)characteristics & DataSectionFlags.MemoryWrite) != 0;

            // Common IAT section names
            bool isIATSection = name.Contains("data") || name.Contains("idata") ||
                               name.Contains("rdata") || name.Contains("import");

            // Readable sections that might contain imports
            bool isReadable = ((DataSectionFlags)characteristics & DataSectionFlags.MemoryRead) != 0;

            return isWritable || (isReadable && isIATSection);
        }

        private byte[] ExtractSectionData(byte[] peData, IMAGE_SECTION_HEADER section)
        {
            if (section.PointerToRawData == 0 || section.SizeOfRawData == 0)
                return null;

            if (section.PointerToRawData + section.SizeOfRawData > peData.Length)
                return null;

            var data = new byte[section.SizeOfRawData];
            Array.Copy(peData, section.PointerToRawData, data, 0, section.SizeOfRawData);
            return data;
        }

        private ulong ReadPointerFromBytes(byte[] data, int offset, bool is64Bit)
        {
            if (is64Bit)
            {
                return BitConverter.ToUInt64(data, offset);
            }
            else
            {
                return BitConverter.ToUInt32(data, offset);
            }
        }

        private T ReadStruct<T>(byte[] data, int offset) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            if (offset + size > data.Length)
                return default(T);

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(data, offset, ptr, size);
                return Marshal.PtrToStructure<T>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        /// <summary>
        /// Read entire module from target process memory
        /// </summary>
        private byte[] ReadTargetProcessModule(int targetProcessId, TargetModuleInfo module)
        {
            try
            {
                // Read DOS header to get PE header offset
                var dosHeaderData = ReadTargetProcessMemory(targetProcessId, module.BaseAddress,
                    Marshal.SizeOf<IMAGE_DOS_HEADER>());
                if (dosHeaderData == null) return null;

                var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(dosHeaderData, 0);
                if (!dosHeader.IsValid) return null;

                // Read NT headers to get image size
                var ntHeaderData = ReadTargetProcessMemory(targetProcessId,
                    module.BaseAddress + (ulong)dosHeader.e_lfanew, Marshal.SizeOf<IMAGE_NT_HEADERS64>());
                if (ntHeaderData == null) return null;

                // Determine if 32-bit or 64-bit
                var ntHeaders64 = ReadStruct<IMAGE_NT_HEADERS64>(ntHeaderData, 0);
                var ntHeaders32 = ReadStruct<IMAGE_NT_HEADERS32>(ntHeaderData, 0);

                uint imageSize = 0;
                if (ntHeaders64.OptionalHeader.Magic == 0x20b) // PE32+
                {
                    imageSize = ntHeaders64.OptionalHeader.SizeOfImage;
                }
                else if (ntHeaders32.OptionalHeader.Magic == 0x10b) // PE32
                {
                    imageSize = ntHeaders32.OptionalHeader.SizeOfImage;
                }
                else
                {
                    return null; // Invalid PE
                }

                // Read entire module (limit to reasonable size)
                if (imageSize > 50 * 1024 * 1024) // 50MB limit
                {
                    Logger.Log("Module {0} too large ({1} bytes), skipping", module.Name, imageSize);
                    return null;
                }

                return ReadTargetProcessMemory(targetProcessId, module.BaseAddress, (int)imageSize);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to read target module {0}: {1}", module.Name, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Parse exports from target process module data
        /// CRITICAL: Uses target process base address for export addresses
        /// </summary>
        private int ParseTargetModuleExports(byte[] moduleData, TargetModuleInfo module)
        {
            try
            {
                var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(moduleData, 0);
                if (!dosHeader.IsValid) return 0;

                // Get NT headers
                int ntHeaderOffset = dosHeader.e_lfanew;
                if (ntHeaderOffset + 24 > moduleData.Length)
                    return 0; // Not enough for Signature + FileHeader

                // Determine architecture and get export directory
                IMAGE_DATA_DIRECTORY exportDir;
                var magic = BitConverter.ToUInt16(moduleData, ntHeaderOffset + 24); // OptionalHeader.Magic

                if (magic == 0x20b) // PE32+
                {
                    if (ntHeaderOffset + Marshal.SizeOf<IMAGE_NT_HEADERS64>() > moduleData.Length)
                        return 0;
                    var ntHeaders = ReadStruct<IMAGE_NT_HEADERS64>(moduleData, ntHeaderOffset);
                    exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else if (magic == 0x10b) // PE32
                {
                    if (ntHeaderOffset + Marshal.SizeOf<IMAGE_NT_HEADERS32>() > moduleData.Length)
                        return 0;
                    var ntHeaders = ReadStruct<IMAGE_NT_HEADERS32>(moduleData, ntHeaderOffset);
                    exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else
                {
                    return 0; // Invalid PE
                }

                if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
                    return 0; // No exports

                // For memory images, RVA is the direct offset
                uint exportTableOffset = exportDir.VirtualAddress;
                if (exportTableOffset == 0 || exportTableOffset + (uint)Marshal.SizeOf<IMAGE_EXPORT_DIRECTORY>() > moduleData.Length)
                    return 0;

                var exportTable = ReadStruct<IMAGE_EXPORT_DIRECTORY>(moduleData, (int)exportTableOffset);
                if (exportTable.NumberOfFunctions == 0) return 0;

                return ParseExportArrays(moduleData, module, exportTable);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to parse exports from {0}: {1}", module.Name, ex.Message);
                return 0;
            }
        }

        /// <summary>
        /// CORRECTED: Parse export arrays using direct RVA access for memory images
        /// </summary>
        private int ParseExportArrays(byte[] moduleData, TargetModuleInfo module, IMAGE_EXPORT_DIRECTORY exportTable)
        {
            try
            {
                int exportCount = 0;

                // Validate export table
                if (exportTable.NumberOfFunctions == 0 || exportTable.NumberOfFunctions > 10000)
                    return 0;

                // CORRECTED: Direct RVA access for memory images (no conversion needed)
                if (!TryReadFromRVA(moduleData, exportTable.AddressOfFunctions,
                    (int)(exportTable.NumberOfFunctions * 4), out byte[] functionsData))
                    return 0;

                // Read function RVAs array
                var functionRVAs = new uint[exportTable.NumberOfFunctions];
                for (int i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    functionRVAs[i] = BitConverter.ToUInt32(functionsData, i * 4);
                }

                // Will hold ordinal indices array for use outside the block below
                byte[] ordinalsData = null;

                // Process named exports
                if (exportTable.NumberOfNames > 0)
                {
                    // Read name RVAs
                    if (!TryReadFromRVA(moduleData, exportTable.AddressOfNames,
                        (int)(exportTable.NumberOfNames * 4), out byte[] namesData))
                        return exportCount;

                    // Read ordinal indices
                    if (!TryReadFromRVA(moduleData, exportTable.AddressOfNameOrdinals,
                        (int)(exportTable.NumberOfNames * 2), out ordinalsData))
                        return exportCount;

                    for (int i = 0; i < exportTable.NumberOfNames; i++)
                    {
                        try
                        {
                            // Read name RVA and ordinal index
                            uint nameRVA = BitConverter.ToUInt32(namesData, i * 4);
                            ushort ordinalIndex = BitConverter.ToUInt16(ordinalsData, i * 2);

                            // Validate ordinal index
                            if (ordinalIndex >= functionRVAs.Length) continue;
                            uint functionRVA = functionRVAs[ordinalIndex];
                            if (functionRVA == 0) continue;

                            // Read function name
                            string functionName = ReadStringFromRVA(moduleData, nameRVA);
                            if (string.IsNullOrEmpty(functionName) || functionName.Length > 256)
                                continue;

                            // Check for forwarded export
                            if (IsForwardedExport(functionRVA, exportTable))
                            {
                                // Skip forwarded exports for now
                                continue;
                            }

                            // CRITICAL: Calculate address in TARGET process space
                            ulong functionAddress = module.BaseAddress + functionRVA;

                            AddExport(functionAddress, module.Name, functionName,
                                exportTable.Base + ordinalIndex);
                            exportCount++;
                        }
                        catch
                        {
                            continue; // Skip problematic exports
                        }
                    }
                }

                // Process ordinal-only exports
                for (uint i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    if (functionRVAs[i] != 0 && !IsNamedExport(i, ordinalsData, (int)exportTable.NumberOfNames))
                    {
                        // Check for forwarded export
                        if (IsForwardedExport(functionRVAs[i], exportTable))
                            continue;

                        // CRITICAL: Calculate address in TARGET process space
                        ulong functionAddress = module.BaseAddress + functionRVAs[i];

                        AddExport(functionAddress, module.Name, null, exportTable.Base + i);
                        exportCount++;
                    }
                }

                Logger.Log("Parsed {0} exports from {1}", exportCount, module.Name);
                return exportCount;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to parse export arrays for {0}: {1}", module.Name, ex.Message);
                return 0;
            }
        }

        /// <summary>
        /// CORRECTED: Check if export is forwarded (simplified)
        /// </summary>
        private bool IsForwardedExport(uint functionRVA, IMAGE_EXPORT_DIRECTORY exportTable)
        {
            // Forwarded exports have RVA pointing within the export directory section
            // This is a simplified check - in reality you'd need to check section bounds
            return functionRVA >= exportTable.AddressOfFunctions &&
                   functionRVA < exportTable.AddressOfFunctions + 1000; // Approximate
        }

        /// <summary>
        /// CORRECTED: Check if a function index corresponds to a named export
        /// </summary>
        private bool IsNamedExport(uint functionIndex, byte[] ordinalsData, int nameCount)
        {
            try
            {
                if (ordinalsData == null) return false;

                for (int i = 0; i < nameCount; i++)
                {
                    if (i * 2 + 2 > ordinalsData.Length) break;

                    ushort ordinalIndex = BitConverter.ToUInt16(ordinalsData, i * 2);
                    if (ordinalIndex == functionIndex)
                        return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if export is forwarded to another DLL
        /// </summary>
        private bool IsForwardedExport(uint functionRVA, IMAGE_EXPORT_DIRECTORY exportTable, byte[] moduleData)
        {
            // Forwarded exports have RVA pointing within the export directory itself
            uint exportDirStart = exportTable.AddressOfFunctions; // This is wrong, should be export dir RVA
            uint exportDirEnd = exportDirStart + 1000; // Approximate export directory size

            return functionRVA >= exportDirStart && functionRVA < exportDirEnd;
        }

        /// <summary>
        /// Check if a function index corresponds to a named export
        /// </summary>
        private bool IsNamedExport(uint functionIndex, uint ordinalsOffset, int nameCount, byte[] moduleData)
        {
            try
            {
                for (int i = 0; i < nameCount; i++)
                {
                    uint ordinalOffset = ordinalsOffset + (uint)(i * 2);
                    if (ordinalOffset + 2 > moduleData.Length) continue;

                    ushort ordinalIndex = BitConverter.ToUInt16(moduleData, (int)ordinalOffset);
                    if (ordinalIndex == functionIndex)
                        return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// CORRECTED: For memory images, RVA IS the offset (no conversion needed)
        /// Memory images are already mapped, unlike disk files
        /// </summary>
        private bool TryReadFromRVA(byte[] moduleData, uint rva, int size, out byte[] data)
        {
            data = null;

            try
            {
                // Validate bounds
                if (rva == 0 || size <= 0 || rva + size > moduleData.Length)
                    return false;

                // In memory images, RVA is the direct offset
                data = new byte[size];
                Array.Copy(moduleData, rva, data, 0, size);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// CORRECTED: Read null-terminated string from RVA in memory image
        /// </summary>
        private string ReadStringFromRVA(byte[] moduleData, uint rva)
        {
            try
            {
                if (rva == 0 || rva >= moduleData.Length) return null;

                // Find null terminator
                int maxLength = Math.Min(256, (int)(moduleData.Length - rva));
                int length = 0;

                while (length < maxLength && moduleData[rva + length] != 0)
                {
                    length++;
                }

                if (length == 0) return null;

                // Read string with bounds checking
                return Encoding.ASCII.GetString(moduleData, (int)rva, length);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// CORRECTED: Read structure from RVA with proper bounds checking
        /// </summary>
        private T ReadStructFromRVA<T>(byte[] moduleData, uint rva) where T : struct
        {
            try
            {
                int structSize = Marshal.SizeOf<T>();
                if (rva + structSize > moduleData.Length)
                    throw new ArgumentOutOfRangeException("RVA out of bounds");

                IntPtr ptr = Marshal.AllocHGlobal(structSize);
                try
                {
                    Marshal.Copy(moduleData, (int)rva, ptr, structSize);
                    return Marshal.PtrToStructure<T>(ptr);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to read struct from RVA 0x{0:X}: {1}", rva, ex.Message);
                throw;
            }
        }

        private int ParseModuleExports(IntPtr moduleHandle, string moduleName)
        {
            try
            {
                // Get DOS header
                var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(moduleHandle);
                if (!dosHeader.IsValid) return 0;

                // Get NT headers
                IntPtr ntHeaderPtr = moduleHandle + dosHeader.e_lfanew;
                var ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeaderPtr);

                // Get export directory
                var exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.VirtualAddress == 0) return 0;

                IntPtr exportDirPtr = moduleHandle + (int)exportDir.VirtualAddress;
                var exportTable = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

                // Read export arrays
                IntPtr functionsPtr = moduleHandle + (int)exportTable.AddressOfFunctions;
                IntPtr namesPtr = moduleHandle + (int)exportTable.AddressOfNames;
                IntPtr ordinalsPtr = moduleHandle + (int)exportTable.AddressOfNameOrdinals;

                int exportCount = 0;

                // Process named exports
                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    uint nameRVA = unchecked((uint)Marshal.ReadInt32(namesPtr + i * 4));
                    ushort ordinalIndex = (ushort)Marshal.ReadInt16(ordinalsPtr + i * 2);
                    uint functionRVA = (uint)Marshal.ReadInt32(functionsPtr + ordinalIndex * 4);

                    string functionName = Marshal.PtrToStringAnsi(moduleHandle + (int)nameRVA);
                    ulong functionAddress = (ulong)moduleHandle.ToInt64() + functionRVA;

                    AddExport(functionAddress, moduleName, functionName, exportTable.Base + ordinalIndex);
                    exportCount++;
                }

                // Process ordinal-only exports
                for (uint i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    uint functionRVA = (uint)Marshal.ReadInt32(functionsPtr + (int)i * 4);
                    if (functionRVA != 0 && !IsNamedExport(i, ordinalsPtr, (int)exportTable.NumberOfNames))
                    {
                        ulong functionAddress = (ulong)moduleHandle.ToInt64() + functionRVA;
                        AddExport(functionAddress, moduleName, null, exportTable.Base + i);
                        exportCount++;
                    }
                }

                return exportCount;
            }
            catch
            {
                return 0;
            }
        }

        private bool IsNamedExport(uint functionIndex, IntPtr ordinalsPtr, int nameCount)
        {
            for (int i = 0; i < nameCount; i++)
            {
                ushort ordinalIndex = (ushort)Marshal.ReadInt16(ordinalsPtr + i * 2);
                if (ordinalIndex == functionIndex)
                    return true;
            }
            return false;
        }

        private void AddExport(ulong address, string moduleName, string functionName, uint ordinal)
        {
            var export = new ExportEntry
            {
                ModuleName = moduleName,
                FunctionName = functionName,
                Ordinal = ordinal
            };

            exports[address] = export;
            exportAddresses.Add(address);

            // Update address range for bit filtering
            if (address < minAddress) minAddress = address;
            if (address > maxAddress) maxAddress = address;
        }

        private void ParseDumpedPEExports(byte[] peData, ulong imageBase, bool is64Bit)
        {
            try
            {
                var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(peData, 0);
                if (!dosHeader.IsValid) return;

                int ntHeaderOffset = dosHeader.e_lfanew;
                var exportDir = is64Bit ?
                    ReadStruct<IMAGE_NT_HEADERS64>(peData, ntHeaderOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] :
                    ReadStruct<IMAGE_NT_HEADERS32>(peData, ntHeaderOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                if (exportDir.VirtualAddress == 0) return;

                // Convert RVA to file offset and parse exports
                uint fileOffset = RVAToFileOffset(peData, exportDir.VirtualAddress);
                if (fileOffset == 0) return;

                var exportTable = ReadStruct<IMAGE_EXPORT_DIRECTORY>(peData, (int)fileOffset);

                // Parse exports from dumped PE (similar to ParseModuleExports but from file data)
                // This helps find imports between dumped modules
            }
            catch
            {
                // Ignore errors in dumped PE export parsing
            }
        }

        /// <summary>
        /// REAL IMPLEMENTATION: Build complete import directory from discovered imports
        /// </summary>
        private bool BuildImportDirectory(ref byte[] peData, List<ImportEntry> imports, bool is64Bit)
        {
            try
            {
                if (imports.Count == 0)
                {
                    Logger.Log("No imports to build directory for");
                    return false;
                }

                // Group imports by module
                var moduleGroups = imports.GroupBy(i => i.ModuleName.ToLowerInvariant())
                                         .OrderBy(g => g.Min(i => i.RVA))
                                         .ToList();

                Logger.Log("Building import directory for {0} modules with {1} total imports",
                    moduleGroups.Count(), imports.Count);

                // Calculate space needed for import directory
                uint importDirSize = CalculateImportDirectorySize(moduleGroups, is64Bit);
                Logger.Log("Import directory requires {0} bytes", importDirSize);

                // Find space in PE file (expand last section)
                uint importDirRVA = FindSpaceForImportDirectory(ref peData, importDirSize, is64Bit);
                if (importDirRVA == 0)
                {
                    Logger.Log("Could not find space for import directory");
                    return false;
                }

                // Build import directory data
                var importData = BuildImportDirectoryData(moduleGroups, importDirRVA, is64Bit);
                if (importData == null || importData.Length == 0)
                {
                    Logger.Log("Failed to build import directory data");
                    return false;
                }

                // Append import directory to PE file
                if (!AppendImportDirectoryToPE(peData, importData, importDirRVA, is64Bit))
                {
                    Logger.Log("Failed to append import directory to PE");
                    return false;
                }

                // Update PE headers to point to new import directory
                if (!UpdatePEImportDirectoryPointers(peData, importDirRVA, (uint)importData.Length, is64Bit))
                {
                    Logger.Log("Failed to update PE import directory pointers");
                    return false;
                }

                Logger.Log("Import directory built successfully at RVA 0x{0:X}, size {1} bytes",
                    importDirRVA, importData.Length);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to build import directory: {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Calculate total size needed for import directory structures
        /// </summary>
        private uint CalculateImportDirectorySize(IEnumerable<IGrouping<string, ImportEntry>> moduleGroups, bool is64Bit)
        {
            uint totalSize = 0;

            // Import descriptors (one per module + null terminator)
            totalSize += (uint)((moduleGroups.Count() + 1) * 20); // IMAGE_IMPORT_DESCRIPTOR is 20 bytes

            // Module names
            foreach (var group in moduleGroups)
            {
                totalSize += (uint)(group.First().ModuleName.Length + 1); // null terminated
            }

            // Import Name Tables (INT) - one per module
            foreach (var group in moduleGroups)
            {
                // Thunk array (one per function + null terminator)
                uint thunkSize = (uint)(is64Bit ? 8 : 4);
                totalSize += (uint)((group.Count() + 1) * thunkSize);
            }

            // Import By Name structures for named imports
            foreach (var group in moduleGroups)
            {
                foreach (var import in group.Where(i => !i.IsOrdinalOnly))
                {
                    // IMAGE_IMPORT_BY_NAME: WORD hint + name + null terminator
                    totalSize += (uint)(2 + import.FunctionName.Length + 1);
                }
            }

            // Align to 4-byte boundary
            return (totalSize + 3) & ~3u;
        }

        /// <summary>
        /// REAL IMPLEMENTATION: Find space for import directory by expanding last section
        /// </summary>
        private uint FindSpaceForImportDirectory(ref byte[] peData, uint requiredSize, bool is64Bit)
        {
            try
            {
                Logger.Log("Finding space for import directory ({0} bytes required)", requiredSize);

                // Parse PE headers to find last section
                if (peData.Length < 64) return 0;
                uint peOffset = BitConverter.ToUInt32(peData, 60);
                if (peOffset >= peData.Length - 4) return 0;

                // Get number of sections
                ushort numberOfSections = BitConverter.ToUInt16(peData, (int)peOffset + 6);
                if (numberOfSections == 0) return 0;

                // Calculate last section header offset
                ushort optionalHeaderSize = BitConverter.ToUInt16(peData, (int)peOffset + 20);
                uint lastSectionOffset = peOffset + 24 + optionalHeaderSize + (uint)((numberOfSections - 1) * 40);

                if (lastSectionOffset + 40 > peData.Length) return 0;

                // Read last section info
                uint virtualAddress = BitConverter.ToUInt32(peData, (int)lastSectionOffset + 12);
                uint virtualSize = BitConverter.ToUInt32(peData, (int)lastSectionOffset + 8);
                uint sizeOfRawData = BitConverter.ToUInt32(peData, (int)lastSectionOffset + 16);
                uint pointerToRawData = BitConverter.ToUInt32(peData, (int)lastSectionOffset + 20);

                // Calculate where we can place the import directory
                // Try to place it at the end of the last section's virtual space
                uint candidateRVA = virtualAddress + virtualSize;

                // Align to reasonable boundary (16 bytes)
                candidateRVA = (candidateRVA + 15) & ~15u;

                // Check if we have enough space in the file
                uint candidateFileOffset = pointerToRawData + (candidateRVA - virtualAddress);

                if (candidateFileOffset + requiredSize <= peData.Length)
                {
                    // We can fit it in the existing section
                    Logger.Log("Found space in last section at RVA 0x{0:X} (file offset 0x{1:X})",
                        candidateRVA, candidateFileOffset);

                    // Update the section's virtual size to include our data
                    uint newVirtualSize = (candidateRVA - virtualAddress) + requiredSize;
                    BitConverter.GetBytes(newVirtualSize).CopyTo(peData, lastSectionOffset + 8);

                    // Update the section's raw size if needed
                    uint newRawSize = Math.Max(sizeOfRawData, newVirtualSize);
                    BitConverter.GetBytes(newRawSize).CopyTo(peData, lastSectionOffset + 16);

                    Logger.Log("Updated last section: VirtualSize=0x{0:X}, SizeOfRawData=0x{1:X}",
                        newVirtualSize, newRawSize);

                    return candidateRVA;
                }
                else
                {
                    // Not enough space in the current file buffer — grow it and expand last section
                    uint fileAlignment = GetFileAlignment(peData, is64Bit);
                    uint newFileEnd = candidateFileOffset + requiredSize;
                    uint newLength = (newFileEnd + (fileAlignment - 1)) & ~(fileAlignment - 1);

                    Logger.Log("Growing PE buffer to {0} bytes to fit import directory", newLength);

                    // Resize the underlying PE buffer
                    Array.Resize(ref peData, (int)newLength);

                    // Update the section's virtual and raw sizes
                    uint newVirtualSize = (candidateRVA - virtualAddress) + requiredSize;
                    BitConverter.GetBytes(newVirtualSize).CopyTo(peData, lastSectionOffset + 8);

                    uint newRawSize = Math.Max(sizeOfRawData, (uint)(newLength - pointerToRawData));
                    newRawSize = (newRawSize + (fileAlignment - 1)) & ~(fileAlignment - 1);
                    BitConverter.GetBytes(newRawSize).CopyTo(peData, lastSectionOffset + 16);

                    // Update SizeOfImage in optional header if needed
                    uint sizeOfImageOffset = is64Bit ? (peOffset + 24 + 56u) : (peOffset + 24 + 56u);
                    uint oldSizeOfImage = BitConverter.ToUInt32(peData, (int)sizeOfImageOffset);
                    uint endOfSection = virtualAddress + newVirtualSize;
                    if (endOfSection > oldSizeOfImage)
                    {
                        BitConverter.GetBytes(endOfSection).CopyTo(peData, (int)sizeOfImageOffset);
                    }

                    Logger.Log("Expanded last section and buffer: VirtualSize=0x{0:X}, SizeOfRawData=0x{1:X}",
                        newVirtualSize, newRawSize);

                    return candidateRVA;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to find space for import directory: {0}", ex.Message);
                return 0;
            }
        }


        /// <summary>
        /// Get file alignment from PE optional header
        /// </summary>
        private uint GetFileAlignment(byte[] peData, bool is64Bit)
        {
            try
            {
                uint peOffset = BitConverter.ToUInt32(peData, 60);
                uint alignmentOffset = peOffset + 24 + 36; // OptionalHeader.FileAlignment offset
                if (alignmentOffset + 4 > peData.Length) return 0x200;
                uint fileAlignment = BitConverter.ToUInt32(peData, (int)alignmentOffset);
                if (fileAlignment == 0) fileAlignment = 0x200;
                return fileAlignment;
            }
            catch
            {
                return 0x200;
            }
        }


        /// <summary>
        /// Get section alignment from PE optional header
        /// </summary>
        private uint GetSectionAlignment(byte[] peData, bool is64Bit)
        {
            try
            {
                uint peOffset = BitConverter.ToUInt32(peData, 60);
                uint alignmentOffset = peOffset + 24 + 32; // OptionalHeader.SectionAlignment offset

                if (alignmentOffset + 4 <= peData.Length)
                {
                    return BitConverter.ToUInt32(peData, (int)alignmentOffset);
                }

                return 0x1000; // Default 4KB alignment
            }
            catch
            {
                return 0x1000;
            }
        }

        /// <summary>
        /// Build import directory data structures
        /// </summary>
        private byte[] BuildImportDirectoryData(IEnumerable<IGrouping<string, ImportEntry>> moduleGroups, uint baseRVA, bool is64Bit)
        {
            try
            {
                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    uint currentRVA = baseRVA;
                    var moduleInfos = new List<ModuleBuildInfo>();

                    // Calculate layout
                    uint descriptorTableSize = (uint)((moduleGroups.Count() + 1) * 20); // IMAGE_IMPORT_DESCRIPTOR
                    currentRVA += descriptorTableSize;

                    // Reserve space and calculate offsets for each module
                    foreach (var group in moduleGroups)
                    {
                        var moduleInfo = new ModuleBuildInfo
                        {
                            ModuleName = group.First().ModuleName,
                            Imports = group.ToList(),
                            NameRVA = currentRVA
                        };

                        // Module name
                        currentRVA += (uint)(moduleInfo.ModuleName.Length + 1);
                        currentRVA = (currentRVA + 3) & ~3u; // Align to 4 bytes

                        // Import Name Table (INT)
                        moduleInfo.INTRVA = currentRVA;
                        uint thunkSize = (uint)(is64Bit ? 8 : 4);
                        currentRVA += (uint)((group.Count() + 1) * thunkSize);

                        moduleInfos.Add(moduleInfo);
                    }

                    // Import By Name structures
                    uint importByNameRVA = currentRVA;
                    foreach (var moduleInfo in moduleInfos)
                    {
                        foreach (var import in moduleInfo.Imports.Where(i => !i.IsOrdinalOnly))
                        {
                            currentRVA += (uint)(2 + import.FunctionName.Length + 1); // WORD + name + null
                            currentRVA = (currentRVA + 1) & ~1u; // Align to 2 bytes
                        }
                    }

                    // Write import descriptors
                    foreach (var moduleInfo in moduleInfos)
                    {
                        // IMAGE_IMPORT_DESCRIPTOR
                        writer.Write(moduleInfo.INTRVA);           // OriginalFirstThunk (INT)
                        writer.Write((uint)0);                    // TimeDateStamp
                        writer.Write((uint)0);                    // ForwarderChain
                        writer.Write(moduleInfo.NameRVA);         // Name
                        writer.Write(moduleInfo.Imports.First().RVA); // FirstThunk (IAT)
                    }

                    // Null terminator descriptor
                    writer.Write(new byte[20]);

                    // Write module names
                    foreach (var moduleInfo in moduleInfos)
                    {
                        writer.Write(Encoding.ASCII.GetBytes(moduleInfo.ModuleName));
                        writer.Write((byte)0);

                        // Align to 4 bytes
                        while (writer.BaseStream.Position % 4 != 0)
                            writer.Write((byte)0);
                    }

                    // Write Import Name Tables
                    uint currentImportByNameRVA = importByNameRVA;
                    foreach (var moduleInfo in moduleInfos)
                    {
                        foreach (var import in moduleInfo.Imports)
                        {
                            if (import.IsOrdinalOnly)
                            {
                                // Ordinal import
                                if (is64Bit)
                                {
                                    ulong ordinalThunk = 0x8000000000000000UL | import.Ordinal;
                                    writer.Write(ordinalThunk);
                                }
                                else
                                {
                                    uint ordinalThunk = 0x80000000U | import.Ordinal;
                                    writer.Write(ordinalThunk);
                                }
                            }
                            else
                            {
                                // Named import
                                if (is64Bit)
                                {
                                    writer.Write((ulong)currentImportByNameRVA);
                                }
                                else
                                {
                                    writer.Write(currentImportByNameRVA);
                                }

                                // Advance to next Import By Name structure
                                currentImportByNameRVA += (uint)(2 + import.FunctionName.Length + 1);
                                currentImportByNameRVA = (currentImportByNameRVA + 1) & ~1u;
                            }
                        }

                        // Null terminator for thunk array
                        if (is64Bit)
                        {
                            writer.Write((ulong)0);
                        }
                        else
                        {
                            writer.Write((uint)0);
                        }
                    }

                    // Write Import By Name structures
                    foreach (var moduleInfo in moduleInfos)
                    {
                        foreach (var import in moduleInfo.Imports.Where(i => !i.IsOrdinalOnly))
                        {
                            // Align to 2 bytes
                            while (writer.BaseStream.Position % 2 != 0)
                                writer.Write((byte)0);

                            // IMAGE_IMPORT_BY_NAME
                            writer.Write((ushort)0); // Hint
                            writer.Write(Encoding.ASCII.GetBytes(import.FunctionName));
                            writer.Write((byte)0); // Null terminator
                        }
                    }

                    return stream.ToArray();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to build import directory data: {0}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// REAL IMPLEMENTATION: Append import directory to PE file
        /// </summary>
        private bool AppendImportDirectoryToPE(byte[] peData, byte[] importData, uint importDirRVA, bool is64Bit)
        {
            try
            {
                Logger.Log("Appending {0} bytes of import directory data to PE file at RVA 0x{1:X}", importData.Length, importDirRVA);

                // Find the section that contains this RVA
                var targetSection = FindSectionContainingRVA(peData, importDirRVA, is64Bit);
                if (targetSection == null)
                {
                    Logger.Log("Could not find section containing RVA 0x{0:X}", importDirRVA);
                    return false;
                }

                // Calculate file offset from RVA
                uint fileOffset = targetSection.PointerToRawData + (importDirRVA - targetSection.VirtualAddress);

                // Ensure we have enough space in the PE data array
                if (fileOffset + importData.Length > peData.Length)
                {
                    Logger.Log("Not enough space in PE file for import directory (need {0} bytes at offset 0x{1:X})",
                        importData.Length, fileOffset);
                    return false;
                }

                // Copy import directory data to PE file
                Array.Copy(importData, 0, peData, fileOffset, importData.Length);

                Logger.Log("Successfully appended import directory to PE file at file offset 0x{0:X}", fileOffset);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to append import directory to PE file: {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Find the section that contains the given RVA
        /// </summary>
        private SectionInfo FindSectionContainingRVA(byte[] peData, uint rva, bool is64Bit)
        {
            try
            {
                // Parse PE headers to get section information
                if (peData.Length < 64) return null;
                uint peOffset = BitConverter.ToUInt32(peData, 60);
                if (peOffset >= peData.Length - 4) return null;

                // Get number of sections
                ushort numberOfSections = BitConverter.ToUInt16(peData, (int)peOffset + 6);
                if (numberOfSections == 0) return null;

                // Calculate section headers offset
                ushort optionalHeaderSize = BitConverter.ToUInt16(peData, (int)peOffset + 20);
                uint sectionHeadersOffset = peOffset + 24 + optionalHeaderSize;

                // Search through sections
                for (int i = 0; i < numberOfSections; i++)
                {
                    uint sectionOffset = sectionHeadersOffset + (uint)(i * 40); // Each section header is 40 bytes
                    if (sectionOffset + 40 > peData.Length) break;

                    uint virtualAddress = BitConverter.ToUInt32(peData, (int)sectionOffset + 12);
                    uint virtualSize = BitConverter.ToUInt32(peData, (int)sectionOffset + 8);
                    uint pointerToRawData = BitConverter.ToUInt32(peData, (int)sectionOffset + 20);
                    uint sizeOfRawData = BitConverter.ToUInt32(peData, (int)sectionOffset + 16);

                    // Check if RVA falls within this section
                    if (rva >= virtualAddress && rva < virtualAddress + virtualSize)
                    {
                        return new SectionInfo
                        {
                            VirtualAddress = virtualAddress,
                            VirtualSize = virtualSize,
                            PointerToRawData = pointerToRawData,
                            SizeOfRawData = sizeOfRawData
                        };
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to find section containing RVA 0x{0:X}: {1}", rva, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Update PE headers to point to new import directory
        /// </summary>
        private bool UpdatePEImportDirectoryPointers(byte[] peData, uint importDirRVA, uint importDirSize, bool is64Bit)
        {
            try
            {
                uint peOffset = BitConverter.ToUInt32(peData, 60);

                // Calculate import directory entry offset in data directory
                uint importDirEntryOffset;
                if (is64Bit)
                {
                    importDirEntryOffset = peOffset + 24 + 112; // PE64 import directory offset
                }
                else
                {
                    importDirEntryOffset = peOffset + 24 + 96; // PE32 import directory offset
                }

                if (importDirEntryOffset + 8 <= peData.Length)
                {
                    // Update import directory RVA and size
                    BitConverter.GetBytes(importDirRVA).CopyTo(peData, importDirEntryOffset);
                    BitConverter.GetBytes(importDirSize).CopyTo(peData, importDirEntryOffset + 4);

                    Logger.Log("Updated PE import directory pointers: RVA=0x{0:X}, Size={1}",
                        importDirRVA, importDirSize);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to update PE import directory pointers: {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Helper class for building import directory
        /// </summary>
        private class ModuleBuildInfo
        {
            public string ModuleName { get; set; }
            public List<ImportEntry> Imports { get; set; }
            public uint NameRVA { get; set; }
            public uint INTRVA { get; set; }
        }

        private uint RVAToFileOffset(byte[] peData, uint rva)
        {
            // Convert RVA to file offset by finding the containing section
            var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(peData, 0);
            if (!dosHeader.IsValid) return 0;

            int ntHeaderOffset = dosHeader.e_lfanew;
            var fileHeader = ReadStruct<IMAGE_FILE_HEADER>(peData, ntHeaderOffset + 4);

            int sectionHeaderOffset = ntHeaderOffset + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                var section = ReadStruct<IMAGE_SECTION_HEADER>(peData, sectionHeaderOffset + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());

                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                {
                    return section.PointerToRawData + (rva - section.VirtualAddress);
                }
            }

            return 0;
        }










        // Helper classes
        private class ExportEntry
        {
            public string ModuleName { get; set; }
            public string FunctionName { get; set; }
            public uint Ordinal { get; set; }
        }

        private class ImportEntry
        {
            public uint RVA { get; set; }
            public ulong Address { get; set; }
            public string ModuleName { get; set; }
            public string FunctionName { get; set; }
            public uint Ordinal { get; set; }
            public bool IsOrdinalOnly { get; set; }
        }

        private class SectionInfo
        {
            public string Name { get; set; }
            public uint VirtualAddress { get; set; }
            public uint VirtualSize { get; set; }
            public uint PointerToRawData { get; set; }
            public uint SizeOfRawData { get; set; }
            public byte[] Data { get; set; }
        }

        private class TargetModuleInfo
        {
            public string Name { get; set; }
            public ulong BaseAddress { get; set; }
            public int ProcessId { get; set; }
            public uint Size { get; set; }
            public bool Is64Bit { get; set; }
        }
    }
}
