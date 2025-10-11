using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using KsDumper11.Driver;
using KsDumper11.PE;
using KsDumper11.Utility;

namespace KsDumper11
{
	// Token: 0x02000003 RID: 3
	public class ProcessDumper
	{
		// Token: 0x0600002E RID: 46 RVA: 0x000038AD File Offset: 0x00001AAD
		public ProcessDumper(KsDumperDriverInterface kernelDriver)
		{
			this.kernelDriver = kernelDriver;
		}

		// Token: 0x0600002F RID: 47 RVA: 0x000038C0 File Offset: 0x00001AC0
		private static bool IsWin64Emulator(Process process)
		{
			bool flag = Environment.OSVersion.Version.Major > 5 || (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1);
			bool retVal;
			return flag && (ProcessDumper.NativeMethods.IsWow64Process(process.Handle, out retVal) && retVal);
		}

		// Token: 0x06000030 RID: 48 RVA: 0x0000392C File Offset: 0x00001B2C
		public bool DumpProcess(Process processSummary, out PEFile outputFile)
		{
			IntPtr basePointer = processSummary.MainModule.BaseAddress;
			NativePEStructs.IMAGE_DOS_HEADER dosHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_DOS_HEADER>(processSummary.Id, basePointer);
			outputFile = null;
			Logger.SkipLine();
			Logger.Log("Targeting Process: {0} ({1})", new object[] { processSummary.ProcessName, processSummary.Id });
			bool isValid = dosHeader.IsValid;
			if (isValid)
			{
				IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;
				Logger.Log("PE Header Found: 0x{0:x8}", new object[] { peHeaderPointer.ToInt64() });
				IntPtr dosStubPointer = basePointer + Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>();
				byte[] dosStub = this.ReadProcessBytes(processSummary.Id, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>());
				bool flag = !ProcessDumper.IsWin64Emulator(processSummary);
				PEFile peFile;
				if (flag)
				{
					peFile = this.Dump64BitPE(processSummary.Id, dosHeader, dosStub, peHeaderPointer);
				}
				else
				{
					peFile = this.Dump32BitPE(processSummary.Id, dosHeader, dosStub, peHeaderPointer);
				}
				bool flag2 = peFile != null;
				if (flag2)
				{
					IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();
					Logger.Log("Header is valid ({0}) !", new object[] { peFile.Type });
					Logger.Log("Parsing {0} Sections...", new object[] { peFile.Sections.Length });
					for (int i = 0; i < peFile.Sections.Length; i++)
					{
						NativePEStructs.IMAGE_SECTION_HEADER sectionHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_SECTION_HEADER>(processSummary.Id, sectionHeaderPointer);
						peFile.Sections[i] = new PESection
						{
							Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
							InitialSize = (int)sectionHeader.VirtualSize
						};
						this.ReadSectionContent(processSummary.Id, new IntPtr(basePointer.ToInt64() + (long)((ulong)sectionHeader.VirtualAddress)), peFile.Sections[i]);
						sectionHeaderPointer += Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>();
					}
					Logger.Log("Aligning Sections...", Array.Empty<object>());
					peFile.AlignSectionHeaders();
					Logger.Log("Fixing PE Header...", Array.Empty<object>());
					peFile.FixPEHeader();

					// CORRECTED ProcessDump-style IAT reconstruction
					Logger.Log("Attempting CORRECTED IAT reconstruction...", Array.Empty<object>());
					var iatReconstructor = new IATReconstructor(this.kernelDriver);

					// Convert PEFile to byte array for processing
					byte[] peBytes = ConvertPEFileToBytes(peFile);
					bool is64Bit = peFile.Type == PEFile.PEType.PE64;
					ulong imageBase = (ulong)basePointer.ToInt64();

					// CRITICAL: Pass target process ID for correct address space
					bool iatFixed = iatReconstructor.ReconstructIAT(ref peBytes, processSummary.Id, imageBase, is64Bit);
					if (iatFixed)
					{
						Logger.Log("IAT reconstruction successful!", Array.Empty<object>());
						// Update PEFile with modified bytes
						UpdatePEFileFromBytes(peFile, peBytes);
					}
					else
					{
						Logger.Log("IAT reconstruction failed - continuing without imports", Array.Empty<object>());
					}

					Logger.Log("Dump Completed !", Array.Empty<object>());
					outputFile = peFile;
					return true;
				}
				Logger.Log("Bad PE Header !", Array.Empty<object>());
			}
			return false;
		}

		// Token: 0x06000031 RID: 49 RVA: 0x00003B80 File Offset: 0x00001D80
		public bool DumpProcess(ProcessSummary processSummary, out PEFile outputFile)
		{
			IntPtr basePointer = (IntPtr)((long)processSummary.MainModuleBase);
			NativePEStructs.IMAGE_DOS_HEADER dosHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_DOS_HEADER>(processSummary.ProcessId, basePointer);
			outputFile = null;
			Logger.SkipLine();
			Logger.Log("Targeting Process: {0} ({1})", new object[] { processSummary.ProcessName, processSummary.ProcessId });
			bool isValid = dosHeader.IsValid;
			if (isValid)
			{
				IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;
				Logger.Log("PE Header Found: 0x{0:x8}", new object[] { peHeaderPointer.ToInt64() });
				IntPtr dosStubPointer = basePointer + Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>();
				byte[] dosStub = this.ReadProcessBytes(processSummary.ProcessId, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<NativePEStructs.IMAGE_DOS_HEADER>());
				bool flag = !processSummary.IsWOW64;
				PEFile peFile;
				if (flag)
				{
					peFile = this.Dump64BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
				}
				else
				{
					peFile = this.Dump32BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
				}
				bool flag2 = peFile != null;
				if (flag2)
				{
					IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();
					Logger.Log("Header is valid ({0}) !", new object[] { peFile.Type });
					Logger.Log("Parsing {0} Sections...", new object[] { peFile.Sections.Length });
					for (int i = 0; i < peFile.Sections.Length; i++)
					{
						NativePEStructs.IMAGE_SECTION_HEADER sectionHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_SECTION_HEADER>(processSummary.ProcessId, sectionHeaderPointer);
						peFile.Sections[i] = new PESection
						{
							Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
							InitialSize = (int)sectionHeader.VirtualSize
						};
						this.ReadSectionContent(processSummary.ProcessId, new IntPtr(basePointer.ToInt64() + (long)((ulong)sectionHeader.VirtualAddress)), peFile.Sections[i]);
						sectionHeaderPointer += Marshal.SizeOf<NativePEStructs.IMAGE_SECTION_HEADER>();
					}
					Logger.Log("Aligning Sections...", Array.Empty<object>());
					peFile.AlignSectionHeaders();
					Logger.Log("Fixing PE Header...", Array.Empty<object>());
					peFile.FixPEHeader();

					// CORRECTED ProcessDump-style IAT reconstruction
					Logger.Log("Attempting CORRECTED IAT reconstruction...", Array.Empty<object>());
					var iatReconstructor = new IATReconstructor(this.kernelDriver);

					// Convert PEFile to byte array for processing
					byte[] peBytes = ConvertPEFileToBytes(peFile);
					bool is64Bit = peFile.Type == PEFile.PEType.PE64;
					ulong imageBase = (ulong)basePointer.ToInt64();

					// CRITICAL: Pass target process ID for correct address space
					bool iatFixed = iatReconstructor.ReconstructIAT(ref peBytes, processSummary.ProcessId, imageBase, is64Bit);
					if (iatFixed)
					{
						Logger.Log("IAT reconstruction successful!", Array.Empty<object>());
						// Update PEFile with modified bytes
						UpdatePEFileFromBytes(peFile, peBytes);
					}
					else
					{
						Logger.Log("IAT reconstruction failed - continuing without imports", Array.Empty<object>());
					}

					Logger.Log("Dump Completed !", Array.Empty<object>());
					outputFile = peFile;
					return true;
				}
				Logger.Log("Bad PE Header !", Array.Empty<object>());
			}
			return false;
		}

		// Token: 0x06000032 RID: 50 RVA: 0x00003DD4 File Offset: 0x00001FD4
		private PEFile Dump64BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
		{
			NativePEStructs.IMAGE_NT_HEADERS64 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS64>(processId, peHeaderPointer);
			bool isValid = peHeader.IsValid;
			PEFile pefile;
			if (isValid)
			{
				pefile = new PE64File(dosHeader, peHeader, dosStub);
			}
			else
			{
				pefile = null;
			}
			return pefile;
		}

		// Token: 0x06000033 RID: 51 RVA: 0x00003E08 File Offset: 0x00002008
		private PEFile Dump32BitPE(int processId, NativePEStructs.IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
		{
			NativePEStructs.IMAGE_NT_HEADERS32 peHeader = this.ReadProcessStruct<NativePEStructs.IMAGE_NT_HEADERS32>(processId, peHeaderPointer);
			bool isValid = peHeader.IsValid;
			PEFile pefile;
			if (isValid)
			{
				pefile = new PE32File(dosHeader, peHeader, dosStub);
			}
			else
			{
				pefile = null;
			}
			return pefile;
		}

		// Token: 0x06000034 RID: 52 RVA: 0x00003E3C File Offset: 0x0000203C
		private T ReadProcessStruct<T>(int processId, IntPtr address) where T : struct
		{
			IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();
			bool flag = this.kernelDriver.CopyVirtualMemory(processId, address, buffer, Marshal.SizeOf<T>());
			T t;
			if (flag)
			{
				t = MarshalUtility.GetStructFromMemory<T>(buffer, true);
			}
			else
			{
				t = default(T);
			}
			return t;
		}

		// Token: 0x06000035 RID: 53 RVA: 0x00003E80 File Offset: 0x00002080
		private bool ReadSectionContent(int processId, IntPtr sectionPointer, PESection section)
		{
			int readSize = section.InitialSize;
			bool flag = sectionPointer == IntPtr.Zero || readSize == 0;
			bool flag2;
			if (flag)
			{
				flag2 = true;
			}
			else
			{
				bool flag3 = readSize <= 100;
				if (flag3)
				{
					section.DataSize = readSize;
					section.Content = this.ReadProcessBytes(processId, sectionPointer, readSize);
					flag2 = true;
				}
				else
				{
					this.CalculateRealSectionSize(processId, sectionPointer, section);
					bool flag4 = section.DataSize != 0;
					if (flag4)
					{
						section.Content = this.ReadProcessBytes(processId, sectionPointer, section.DataSize);
						flag2 = true;
					}
					else
					{
						flag2 = false;
					}
				}
			}
			return flag2;
		}

		// Token: 0x06000036 RID: 54 RVA: 0x00003F18 File Offset: 0x00002118
		private byte[] ReadProcessBytes(int processId, IntPtr address, int size)
		{
			IntPtr unmanagedBytePointer = MarshalUtility.AllocZeroFilled(size);
			this.kernelDriver.CopyVirtualMemory(processId, address, unmanagedBytePointer, size);
			byte[] buffer = new byte[size];
			Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
			Marshal.FreeHGlobal(unmanagedBytePointer);
			return buffer;
		}

		// Token: 0x06000037 RID: 55 RVA: 0x00003F5C File Offset: 0x0000215C
		private void CalculateRealSectionSize(int processId, IntPtr sectionPointer, PESection section)
		{
			int readSize = section.InitialSize;
			int currentReadSize = readSize % 100;
			bool flag = currentReadSize == 0;
			if (flag)
			{
				currentReadSize = 100;
			}
			IntPtr currentOffset = sectionPointer + readSize - currentReadSize;
			while (currentOffset.ToInt64() >= sectionPointer.ToInt64())
			{
				byte[] buffer = this.ReadProcessBytes(processId, currentOffset, currentReadSize);
				int codeByteCount = this.GetInstructionByteCount(buffer);
				bool flag2 = codeByteCount != 0;
				if (flag2)
				{
					currentOffset += codeByteCount;
					bool flag3 = sectionPointer.ToInt64() < currentOffset.ToInt64();
					if (flag3)
					{
						section.DataSize = (int)(currentOffset.ToInt64() - sectionPointer.ToInt64());
						section.DataSize += 4;
						bool flag4 = section.InitialSize < section.DataSize;
						if (flag4)
						{
							section.DataSize = section.InitialSize;
						}
					}
					break;
				}
				currentReadSize = 100;
				currentOffset -= currentReadSize;
			}
		}

		// Token: 0x06000038 RID: 56 RVA: 0x0000404C File Offset: 0x0000224C
		private int GetInstructionByteCount(byte[] dataBlock)
		{
			for (int i = dataBlock.Length - 1; i >= 0; i--)
			{
				bool flag = dataBlock[i] > 0;
				if (flag)
				{
					return i + 1;
				}
			}
			return 0;
		}

		/// <summary>
		/// Convert PEFile to byte array for IAT reconstruction
		/// </summary>
		private byte[] ConvertPEFileToBytes(PEFile peFile)
		{
			using (var stream = new MemoryStream())
			{
				using (var writer = new BinaryWriter(stream))
				{
					// Write DOS header
					if (peFile.Type == PEFile.PEType.PE32)
					{
						var pe32 = (PE32File)peFile;
						pe32.DOSHeader.AppendToStream(writer);
						writer.Write(pe32.DOS_Stub);
						pe32.PEHeader.AppendToStream(writer);
					}
					else
					{
						var pe64 = (PE64File)peFile;
						pe64.DOSHeader.AppendToStream(writer);
						writer.Write(pe64.DOS_Stub);
						pe64.PEHeader.AppendToStream(writer);
					}

					// Write section headers
					foreach (var section in peFile.Sections)
					{
						section.Header.AppendToStream(writer);
					}

					// Write section data
					foreach (var section in peFile.Sections)
					{
						if (section.Header.PointerToRawData > 0 && section.Content != null)
						{
							// Pad to section start if needed
							while (writer.BaseStream.Position < section.Header.PointerToRawData)
							{
								writer.Write((byte)0);
							}

							writer.Write(section.Content);

							// Pad section to aligned size
							while (writer.BaseStream.Position < section.Header.PointerToRawData + section.Header.SizeOfRawData)
							{
								writer.Write((byte)0);
							}
						}
					}
				}

				return stream.ToArray();
			}
		}

		/// <summary>
		/// REAL IMPLEMENTATION: Update PEFile from modified byte array after IAT reconstruction
		/// </summary>
		private void UpdatePEFileFromBytes(PEFile peFile, byte[] modifiedBytes)
		{
			try
			{
				Logger.Log("Updating PEFile with IAT-fixed data ({0} bytes)", modifiedBytes.Length);

				// Parse the modified bytes to extract import directory information
				var importInfo = ExtractImportDirectoryInfo(modifiedBytes);
				if (importInfo == null)
				{
					Logger.Log("No import directory found in modified bytes");
					return;
				}

				// FIXED: Actually update the PE file's section data with import directory
				if (!UpdatePESectionData(peFile, modifiedBytes, importInfo))
				{
					Logger.Log("Failed to update PE section data");
					return;
				}

				// Update the PE file's import directory headers
				UpdatePEImportDirectory(peFile, importInfo);

				Logger.Log("Successfully updated PEFile with {0} import modules", importInfo.ModuleCount);
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to update PEFile from modified bytes: {0}", ex.Message);
			}
		}

		/// <summary>
		/// REAL IMPLEMENTATION: Update PE file section data with import directory
		/// </summary>
		private bool UpdatePESectionData(PEFile peFile, byte[] modifiedBytes, ImportDirectoryInfo importInfo)
		{
			try
			{
				// Find the section that contains the import directory
				var targetSection = FindSectionContainingRVA(peFile, importInfo.RVA);
				if (targetSection == null)
				{
					Logger.Log("Could not find section containing import directory RVA 0x{0:X}", importInfo.RVA);
					return false;
				}

				// Calculate offset within the section
				uint sectionOffset = importInfo.RVA - targetSection.Header.VirtualAddress;

				// Extract import directory data from modified bytes
				uint fileOffset = targetSection.Header.PointerToRawData + sectionOffset;
				if (fileOffset + importInfo.Size > modifiedBytes.Length)
				{
					Logger.Log("Import directory extends beyond PE file bounds");
					return false;
				}

				// FIXED: Actually copy the import directory data to the section
				byte[] importData = new byte[importInfo.Size];
				Array.Copy(modifiedBytes, fileOffset, importData, 0, importInfo.Size);

				// Expand section content if necessary
				if (targetSection.Content == null || targetSection.Content.Length < sectionOffset + importInfo.Size)
				{
					byte[] newContent = new byte[sectionOffset + importInfo.Size];
					if (targetSection.Content != null)
					{
						Array.Copy(targetSection.Content, 0, newContent, 0, Math.Min(targetSection.Content.Length, newContent.Length));
					}
					targetSection.Content = newContent;
				}

				// Copy import directory data to section
				Array.Copy(importData, 0, targetSection.Content, sectionOffset, importInfo.Size);

				// Update section header sizes
				uint newVirtualSize = Math.Max(targetSection.Header.VirtualSize, sectionOffset + importInfo.Size);
				uint newRawSize = Math.Max(targetSection.Header.SizeOfRawData, newVirtualSize);

				targetSection.Header.VirtualSize = newVirtualSize;
				targetSection.Header.SizeOfRawData = newRawSize;

				Logger.Log("Updated section {0}: VirtualSize=0x{1:X}, SizeOfRawData=0x{2:X}",
					targetSection.Header.Name, newVirtualSize, newRawSize);

				return true;
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to update PE section data: {0}", ex.Message);
				return false;
			}
		}

		/// <summary>
		/// REAL IMPLEMENTATION: Find the section that contains the given RVA
		/// </summary>
		private PESection FindSectionContainingRVA(PEFile peFile, uint rva)
		{
			try
			{
				foreach (var section in peFile.Sections)
				{
					uint sectionStart = section.Header.VirtualAddress;
					uint sectionEnd = sectionStart + section.Header.VirtualSize;

					if (rva >= sectionStart && rva < sectionEnd)
					{
						Logger.Log("Found RVA 0x{0:X} in section {1} (0x{2:X}-0x{3:X})",
							rva, section.Header.Name, sectionStart, sectionEnd);
						return section;
					}
				}

				Logger.Log("RVA 0x{0:X} not found in any existing section - need to create new section", rva);

				// FIXED: If RVA not found, try to create a new section
				return CreateNewSectionForImports(peFile, rva);
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to find section containing RVA 0x{0:X}: {1}", rva, ex.Message);
				return null;
			}
		}

		/// <summary>
		/// REAL IMPLEMENTATION: Create new section for import directory if needed
		/// </summary>
		private PESection CreateNewSectionForImports(PEFile peFile, uint targetRVA)
		{
			try
			{
				Logger.Log("Creating new section for import directory at RVA 0x{0:X}", targetRVA);

				// FIXED: Proper null checking for sections
				if (peFile.Sections == null || peFile.Sections.Length == 0)
				{
					Logger.Log("No existing sections found - cannot create new section");
					return null;
				}

				// Find the last section to calculate new section placement
				var lastSection = peFile.Sections.LastOrDefault();
				if (lastSection == null)
				{
					Logger.Log("Failed to get last section - cannot create new section");
					return null;
				}

				// Calculate new section RVA (aligned to section alignment, typically 0x1000)
				uint sectionAlignment = 0x1000; // Standard section alignment
				uint lastSectionEnd = lastSection.Header.VirtualAddress + lastSection.Header.VirtualSize;
				uint newSectionRVA = (lastSectionEnd + sectionAlignment - 1) & ~(sectionAlignment - 1);

				// If target RVA is beyond our calculated position, use target RVA
				if (targetRVA > newSectionRVA)
				{
					newSectionRVA = (targetRVA & ~(sectionAlignment - 1)); // Align down to section boundary
				}

				// Calculate file offset (aligned to file alignment, typically 0x200)
				uint fileAlignment = 0x200; // Standard file alignment
				uint lastSectionFileEnd = lastSection.Header.PointerToRawData + lastSection.Header.SizeOfRawData;
				uint newSectionFileOffset = (lastSectionFileEnd + fileAlignment - 1) & ~(fileAlignment - 1);

				// Create new section header
				var newSectionHeader = new PESection.PESectionHeader
				{
					Name = ".idata", // Standard import section name
					VirtualSize = 0x1000, // Initial size - will be updated as needed
					VirtualAddress = newSectionRVA,
					SizeOfRawData = 0x1000, // Aligned size
					PointerToRawData = newSectionFileOffset,
					Characteristics = (NativePEStructs.DataSectionFlags)0x40000040 // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
				};

				// Create new section with empty content
				var newSection = new PESection
				{
					Header = newSectionHeader,
					Content = new byte[0x1000] // Initialize with zeros
				};

				// FIXED: Actually update the PEFile object
				var sectionsList = peFile.Sections.ToList();
				sectionsList.Add(newSection);

				// CRITICAL: Update the PEFile sections (this line was missing!)
				peFile.Sections = sectionsList.ToArray();

				// CRITICAL: Update PE header section count and image size
				if (peFile.Type == PEFile.PEType.PE32)
				{
					var pe32 = (PE32File)peFile;
					pe32.PEHeader.FileHeader.NumberOfSections++;

					// Update image size
					uint newImageSize = newSectionRVA + newSectionHeader.VirtualSize;
					pe32.PEHeader.OptionalHeader.SizeOfImage = newImageSize;

					Logger.Log("Updated PE32 headers: sections={0}, imageSize=0x{1:X}",
						pe32.PEHeader.FileHeader.NumberOfSections, newImageSize);
				}
				else if (peFile.Type == PEFile.PEType.PE64)
				{
					var pe64 = (PE64File)peFile;
					pe64.PEHeader.FileHeader.NumberOfSections++;

					// Update image size
					uint newImageSize = newSectionRVA + newSectionHeader.VirtualSize;
					pe64.PEHeader.OptionalHeader.SizeOfImage = newImageSize;

					Logger.Log("Updated PE64 headers: sections={0}, imageSize=0x{1:X}",
						pe64.PEHeader.FileHeader.NumberOfSections, newImageSize);
				}

				Logger.Log("Created new section .idata at RVA 0x{0:X}, file offset 0x{1:X}",
					newSectionRVA, newSectionFileOffset);

				return newSection;
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to create new section for imports: {0}", ex.Message);
				return null;
			}
		}

		/// <summary>
		/// Extract import directory information from modified PE bytes
		/// </summary>
		private ImportDirectoryInfo ExtractImportDirectoryInfo(byte[] peBytes)
		{
			try
			{
				if (peBytes.Length < 64) return null;

				// Parse DOS header
				uint peOffset = BitConverter.ToUInt32(peBytes, 60);
				if (peOffset >= peBytes.Length - 4) return null;

				// Determine architecture
				ushort machine = BitConverter.ToUInt16(peBytes, (int)peOffset + 4);
				bool is64Bit = machine == 0x8664;

				// Get import directory RVA and size from data directory
				uint importDirOffset = is64Bit ?
					peOffset + 24 + 112 : // PE64 import directory offset
					peOffset + 24 + 96;   // PE32 import directory offset

				if (importDirOffset + 8 > peBytes.Length) return null;

				uint importDirRVA = BitConverter.ToUInt32(peBytes, (int)importDirOffset);
				uint importDirSize = BitConverter.ToUInt32(peBytes, (int)importDirOffset + 4);

				if (importDirRVA == 0 || importDirSize == 0) return null;

				// Count import modules by parsing import descriptors
				int moduleCount = CountImportModules(peBytes, importDirRVA);

				return new ImportDirectoryInfo
				{
					RVA = importDirRVA,
					Size = importDirSize,
					ModuleCount = moduleCount
				};
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to extract import directory info: {0}", ex.Message);
				return null;
			}
		}

		/// <summary>
		/// Count the number of import modules in the import directory
		/// </summary>
		private int CountImportModules(byte[] peBytes, uint importDirRVA)
		{
			try
			{
				int count = 0;
				uint currentOffset = importDirRVA;

				// Each import descriptor is 20 bytes
				while (currentOffset + 20 <= peBytes.Length)
				{
					// Check if this is the null terminator descriptor
					bool isNull = true;
					for (int i = 0; i < 20; i++)
					{
						if (peBytes[currentOffset + i] != 0)
						{
							isNull = false;
							break;
						}
					}

					if (isNull) break;

					count++;
					currentOffset += 20;

					// Safety limit
					if (count > 100) break;
				}

				return count;
			}
			catch
			{
				return 0;
			}
		}

		/// <summary>
		/// REAL IMPLEMENTATION: Update PE file's import directory pointers
		/// </summary>
		private void UpdatePEImportDirectory(PEFile peFile, ImportDirectoryInfo importInfo)
		{
			try
			{
				Logger.Log("Updating PE file structure with import directory: RVA=0x{0:X}, Size={1}, Modules={2}",
					importInfo.RVA, importInfo.Size, importInfo.ModuleCount);

				// Update the PE file's data directory entry for imports
				if (peFile.Type == PEFile.PEType.PE32)
				{
					var pe32 = (PE32File)peFile;
					// Update import directory in optional header
					pe32.PEHeader.OptionalHeader.DataDirectory[1].VirtualAddress = importInfo.RVA;
					pe32.PEHeader.OptionalHeader.DataDirectory[1].Size = importInfo.Size;
					Logger.Log("Updated PE32 import directory pointers");
				}
				else if (peFile.Type == PEFile.PEType.PE64)
				{
					var pe64 = (PE64File)peFile;
					// Update import directory in optional header
					pe64.PEHeader.OptionalHeader.DataDirectory[1].VirtualAddress = importInfo.RVA;
					pe64.PEHeader.OptionalHeader.DataDirectory[1].Size = importInfo.Size;
					Logger.Log("Updated PE64 import directory pointers");
				}

				// If import directory was added to a new section, we would need to:
				// 1. Add the new section to peFile.Sections
				// 2. Update section count in PE header
				// 3. Recalculate file alignment
				// For now, we assume it was added to an existing section

				Logger.Log("Successfully updated PE file structure with import directory");
			}
			catch (Exception ex)
			{
				Logger.Log("Failed to update PE import directory: {0}", ex.Message);
			}
		}

		/// <summary>
		/// Helper class for import directory information
		/// </summary>
		private class ImportDirectoryInfo
		{
			public uint RVA { get; set; }
			public uint Size { get; set; }
			public int ModuleCount { get; set; }
		}

		// Token: 0x0400002B RID: 43
		private KsDumperDriverInterface kernelDriver;

		// Token: 0x02000023 RID: 35
		internal static class NativeMethods
		{
			// Token: 0x060000EF RID: 239
			[DllImport("kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			internal static extern bool IsWow64Process([In] IntPtr process, out bool wow64Process);
		}
	}
}
