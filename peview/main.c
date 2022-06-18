#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

#define _CRT_SECURE_NO_WARNINGS

char* data_directory_name[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
"Export Table","Import Table","Resource Table","Exception Table",
"Security Table","Base Relocation Table",
"Debug Table","Copyright/Architecture Table","Global Pointers Table","TLS Table",
"Load Configuration Table","Bound Import Table",
"IAT Table","Delay Import Table","Com Descriptors Table", "Reserved (N/U)" };

void print_string(char* msg, int file, int offset)
{
	char c = 1;

	lseek(file, offset, SEEK_SET);
	printf("%s", msg);

	while (read(file, &c, sizeof(c) && c)) printf("%c", c);
}

int print_image_nt_headers(IMAGE_NT_HEADERS32* pH)
{
	int i;

	if (pH->Signature != 0x4550)
	{
		printf("print_image_nt_headers: main header is not PE\n");
		return -1;
	}
	printf("DWORD ImNTHeaders.Signature: 0x%.8lX\n\n", pH->Signature);

	printf("WORD  ImNTHeaders.ImFileHeader.Machine: 0x%.4X\n", pH->FileHeader.Machine);
	printf("WORD  ImNTHeaders.ImFileHeader.NumberOfSections: 0x%.4X (%d)\n", pH->FileHeader.NumberOfSections, pH->FileHeader.NumberOfSections);
	printf("DWORD ImNTHeaders.ImFileHeader.TimeDateStamp: 0x%.8lX %s", pH->FileHeader.TimeDateStamp, ctime((time_t*)&(pH->FileHeader.TimeDateStamp)));
	printf("DWORD ImNTHeaders.ImFileHeader.PointerToSymbolTable: 0x%.8lX\n", pH->FileHeader.PointerToSymbolTable);
	printf("DWORD ImNTHeaders.ImFileHeader.NumberOfSymbols: 0x%.8lX (%ld)\n", pH->FileHeader.NumberOfSymbols, pH->FileHeader.NumberOfSymbols);
	printf("WORD  ImNTHeaders.ImFileHeader.SizeOfOptionalHeader: 0x%.4X (%d)\n", pH->FileHeader.SizeOfOptionalHeader, pH->FileHeader.SizeOfOptionalHeader);
	printf("WORD  ImNTHeaders.ImFileHeader.Characteristics: 0x%.4X\n\n", pH->FileHeader.Characteristics);

	printf("WORD  ImNTHeaders.OptHeader.Magic: 0x%.4X\n", pH->OptionalHeader.Magic);
	printf("BYTE  ImNTHeaders.OptHeader.MajorLinkerVersion: 0x%.2X (%d)\n", pH->OptionalHeader.MajorLinkerVersion, pH->OptionalHeader.MajorLinkerVersion);
	printf("BYTE  ImNTHeaders.OptHeader.MinorLinkerVersion: 0x%.2X (%d)\n", pH->OptionalHeader.MinorLinkerVersion, pH->OptionalHeader.MinorLinkerVersion);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfCode: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfCode, pH->OptionalHeader.SizeOfCode);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfInitializedData: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfInitializedData, pH->OptionalHeader.SizeOfInitializedData);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfUninitializedData: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfUninitializedData, pH->OptionalHeader.SizeOfUninitializedData);
	printf("DWORD ImNTHeaders.OptHeader.AddressOfEntryPoint: 0x%.8lX\n", pH->OptionalHeader.AddressOfEntryPoint);
	printf("DWORD ImNTHeaders.OptHeader.BaseOfCode: 0x%.8lX\n", pH->OptionalHeader.BaseOfCode);
	printf("DWORD ImNTHeaders.OptHeader.BaseOfData: 0x%.8lX\n", pH->OptionalHeader.BaseOfData);
	printf("DWORD ImNTHeaders.OptHeader.ImageBase: 0x%.8lX\n", pH->OptionalHeader.ImageBase);
	printf("DWORD ImNTHeaders.OptHeader.SectionAlignment: 0x%.8lX (%ld)\n", pH->OptionalHeader.SectionAlignment, pH->OptionalHeader.SectionAlignment);
	printf("DWORD ImNTHeaders.OptHeader.FileAlignment: 0x%.8lX (%ld)\n", pH->OptionalHeader.FileAlignment, pH->OptionalHeader.FileAlignment);
	printf("WORD  ImNTHeaders.OptHeader.MajorOperatingSystemVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MajorOperatingSystemVersion, pH->OptionalHeader.MajorOperatingSystemVersion);
	printf("WORD  ImNTHeaders.OptHeader.MinorOperatingSystemVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MinorOperatingSystemVersion, pH->OptionalHeader.MinorOperatingSystemVersion);
	printf("WORD  ImNTHeaders.OptHeader.MajorImageVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MajorImageVersion, pH->OptionalHeader.MajorImageVersion);
	printf("WORD  ImNTHeaders.OptHeader.MinorImageVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MinorImageVersion, pH->OptionalHeader.MinorImageVersion);
	printf("WORD  ImNTHeaders.OptHeader.MajorSubsystemVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MajorSubsystemVersion, pH->OptionalHeader.MajorSubsystemVersion);
	printf("WORD  ImNTHeaders.OptHeader.MinorSubsystemVersion: 0x%.4X (%d)\n", pH->OptionalHeader.MinorSubsystemVersion, pH->OptionalHeader.MinorSubsystemVersion);
	printf("DWORD ImNTHeaders.OptHeader.Win32VersionValue: 0x%.8lX (%ld)\n", pH->OptionalHeader.Win32VersionValue, pH->OptionalHeader.Win32VersionValue);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfImage: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfImage, pH->OptionalHeader.SizeOfImage);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfHeaders: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfHeaders, pH->OptionalHeader.SizeOfHeaders);
	printf("DWORD ImNTHeaders.OptHeader.CheckSum: 0x%.8lX (%ld)\n", pH->OptionalHeader.CheckSum, pH->OptionalHeader.CheckSum);
	printf("WORD  ImNTHeaders.OptHeader.Subsystem: 0x%.4X (%d)\n", pH->OptionalHeader.Subsystem, pH->OptionalHeader.Subsystem);
	printf("WORD  ImNTHeaders.OptHeader.DllCharacteristics: 0x%.4X\n", pH->OptionalHeader.DllCharacteristics);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfStackReserve: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfStackReserve, pH->OptionalHeader.SizeOfStackReserve);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfStackCommit: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfStackCommit, pH->OptionalHeader.SizeOfStackCommit);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfHeapReserve: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfHeapReserve, pH->OptionalHeader.SizeOfHeapReserve);
	printf("DWORD ImNTHeaders.OptHeader.SizeOfHeapCommit: 0x%.8lX (%ld)\n", pH->OptionalHeader.SizeOfHeapCommit, pH->OptionalHeader.SizeOfHeapCommit);
	printf("DWORD ImNTHeaders.OptHeader.LoaderFlags: 0x%.8lX\n", pH->OptionalHeader.LoaderFlags);
	printf("DWORD ImNTHeaders.OptHeader.NumberOfRvaAndSizes: 0x%.8lX (%ld)\n\n", pH->OptionalHeader.NumberOfRvaAndSizes, pH->OptionalHeader.NumberOfRvaAndSizes);

	printf("Number of Directory Entries: 0x%X (%d)\n\n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

	for (i = 0;i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++)
	{
		printf("Directory Entry #%d named %s\n", i, data_directory_name[i]);
		printf("DWORD ImNTHeaders.OptHeader.DataDirectory[%d].VirtualAddress: 0x%.8lX\n", i, pH->OptionalHeader.DataDirectory[i].VirtualAddress);
		printf("DWORD ImNTHeaders.OptHeader.DataDirectory[%d].Size: 0x%.8lX (%ld)\n\n", i, pH->OptionalHeader.DataDirectory[i].Size, pH->OptionalHeader.DataDirectory[i].Size);
	}
	return 0;
}

void print_image_section_headers(PIMAGE_SECTION_HEADER pS, int num_of_sections)
{
	int i, j;
	for (i = 0; i < num_of_sections;i++)
	{
		printf("ImgSectionHeader[%d].Name:", i);
		for (j = 0;j < IMAGE_SIZEOF_SHORT_NAME;j++)
			printf("%c", pS[i].Name[j]);
		printf("\n");

		printf("DWORD ImgSectionHeader[%d].Misc.PhysicalAddress: 0x%.8lX\n", i, pS[i].Misc.PhysicalAddress);
		printf("DWORD ImgSectionHeader[%d].Misc.VirtualSize: 0x%.8lX (%ld)\n", i, pS[i].Misc.VirtualSize, pS[i].Misc.VirtualSize);
		printf("DWORD ImgSectionHeader[%d].VirtualAddress: 0x%.8lX\n", i, pS[i].VirtualAddress);
		printf("DWORD ImgSectionHeader[%d].SizeOfRawData: 0x%.8lX (%ld)\n", i, pS[i].SizeOfRawData, pS[i].SizeOfRawData);
		printf("DWORD ImgSectionHeader[%d].PointerToRawData: 0x%.8lX\n", i, pS[i].PointerToRawData);
		printf("DWORD ImgSectionHeader[%d].PointerToRelocations: 0x%.8lX\n", i, pS[i].PointerToRelocations);
		printf("DWORD ImgSectionHeader[%d].PointerToLinenumbers: 0x%.8lX\n", i, pS[i].PointerToLinenumbers);
		printf("WORD  ImgSectionHeader[%d].NumberOfRelocations: 0x%.4X (%d)\n", i, pS[i].NumberOfRelocations, pS[i].NumberOfRelocations);
		printf("WORD  ImgSectionHeader[%d].NumberOfLinenumbers: 0x%.4X (%d)\n", i, pS[i].NumberOfLinenumbers, pS[i].NumberOfLinenumbers);
		printf("DWORD ImgSectionHeader[%d].Characteristics: 0x%.8lX\n", i, pS[i].Characteristics);
		printf("\n");
	}
}

void print_export_metadata_and_tables(int pe_file, PIMAGE_SECTION_HEADER pS,
	int num_of_sections, DWORD ied_v_offset,
	DWORD ied_size, int flag)
{

	int i;
	int export_section;
	int delta_export_offset;
	int ied_file_offset = 0;
	DWORD function_offset = 0;
	DWORD addr_function = 0;
	WORD ordinal = 0;
	PIMAGE_EXPORT_DIRECTORY pE;
	IMAGE_EXPORT_DIRECTORY ied;

	pE = &ied;


	//Thanks to Sang Cho, assistant professor at 
	// the department of 
	// computer science and engineering
	//	chongju university, author pedump
	// return (LPVOID)(((int)lpFile + (int)VAImageDir - psh->VirtualAddress) +
	//				   (int)psh->PointerToRawData);
	for (i = 0;i < num_of_sections;i++)
		if (ied_v_offset >= pS[i].VirtualAddress && ied_v_offset <= pS[i].VirtualAddress + pS[i].Misc.VirtualSize) break;


	export_section = i;
	printf("Export section: #%d\n\n", export_section);

	delta_export_offset = pS[export_section].PointerToRawData - pS[export_section].VirtualAddress;
	printf("-delta export offset: 0x%.8X\n\n", -delta_export_offset);
	ied_file_offset = ied_v_offset + delta_export_offset;

	lseek(pe_file, ied_file_offset, SEEK_SET);

	read(pe_file, pE, sizeof(IMAGE_EXPORT_DIRECTORY));

	printf("DWORD ImgExportDir.Characteristics: 0x%.8lX\n", pE->Characteristics);
	printf("DWORD ImgExportDir.TimeDateState: 0x%.8lX %s", pE->TimeDateStamp, ctime((time_t*)&(pE->TimeDateStamp)));
	printf("WORD  ImgExportDir.MajorVersion: 0x%.4X (%d)\n", pE->MajorVersion, pE->MajorVersion);
	printf("WORD  ImgExportDir.MinorVersion: 0x%.4X (%d)\n", pE->MinorVersion, pE->MinorVersion);
	printf("DWORD ImgExportDir.Name: 0x%.8lX\n", pE->Name);
	printf("DWORD ImgExportDir.Base: 0x%.8lX\n", pE->Base);
	printf("DWORD ImgExportDir.NumberOfFunctions: 0x%.8lX (%ld)\n", pE->NumberOfFunctions, pE->NumberOfFunctions);
	printf("DWORD ImgExportDir.NumberOfNames: 0x%.8lX (%ld)\n", pE->NumberOfNames, pE->NumberOfNames);
	printf("DWORD ImgExportDir.AddressOfFunctions: 0x%.8lX\n", pE->AddressOfFunctions);
	printf("DWORD ImgExportDir.AddressOfNames: 0x%.8lX\n", pE->AddressOfNames);
	printf("DWORD ImgExportDir.AddressOfNameOrdinals: 0x%.8lX\n", pE->AddressOfNameOrdinals);

	print_string("\nLibrary Name: ", pe_file, ied.Name + delta_export_offset);

	if (flag)
	{
		if (ied.NumberOfNames > 0)
		{
			printf("\n\nNamed function export table:\n");

			for (i = 0;i < ied.NumberOfNames;i++)
			{
				lseek(pe_file, ied.AddressOfNames + i * sizeof(function_offset) + delta_export_offset, SEEK_SET);
				read(pe_file, &function_offset, sizeof(function_offset));
				printf("#%d ", i);
				print_string(" name/ordinal/address: ", pe_file, function_offset + delta_export_offset);

				lseek(pe_file, ied.AddressOfNameOrdinals + i * sizeof(ordinal) + delta_export_offset, SEEK_SET);
				read(pe_file, &ordinal, sizeof(ordinal));
				printf(" %ld ", ordinal + ied.Base);


				lseek(pe_file, ied.AddressOfFunctions + ordinal * sizeof(addr_function) + delta_export_offset, SEEK_SET);
				read(pe_file, &addr_function, sizeof(addr_function));
				printf(" 0x%.8lX\n", addr_function);
			}
		}
		if (ied.NumberOfFunctions != ied.NumberOfNames)
		{
			printf("\nAll function export table\n");
			for (i = 0;i < ied.NumberOfFunctions;i++)
			{
				int fl_fwd = 0;
				int fl_null = 0;

				printf("#%d ordinal/address: %ld ", i, i + ied.Base);
				lseek(pe_file, ied.AddressOfFunctions + i * sizeof(addr_function) + delta_export_offset, SEEK_SET);
				read(pe_file, &addr_function, sizeof(addr_function));

				if (addr_function >= ied_v_offset &&
					addr_function <= ied_v_offset + ied_size) fl_fwd = 1;

				if (addr_function == 0) fl_null = 1;

				printf(" 0x%.8lX %s%s", addr_function, fl_fwd ? "FWD" : "", fl_null ? "NULL" : "");
				//if(fl_fwd) print_string("",pe_file,addr_function+delta_export_offset);
				printf("\n");
			}
		}
	}
}

void print_std_import_metadata_and_tables(int pe_file, PIMAGE_SECTION_HEADER pS,
	int num_of_sections, DWORD istdid_v_offset,
	DWORD istdid_size, int flag)
{
	int i;
	int std_import_section;
	int delta_std_import_offset;
	int istdid_file_offset = 0;
	IMAGE_IMPORT_DESCRIPTOR iid;

	for (i = 0;i < num_of_sections;i++)
		if (istdid_v_offset >= pS[i].VirtualAddress &&
			istdid_v_offset <= pS[i].VirtualAddress + pS[i].Misc.VirtualSize) break;

	std_import_section = i;
	printf("\nStandard import section: #%d\n\n", std_import_section);

	delta_std_import_offset = pS[std_import_section].PointerToRawData - pS[std_import_section].VirtualAddress;
	printf("-delta standard import offset: 0x%.8X\n\n", -delta_std_import_offset);

	istdid_file_offset = istdid_v_offset + delta_std_import_offset;


	lseek(pe_file, istdid_file_offset, SEEK_SET);
	i = 0;

	do
	{
		read(pe_file, &iid, sizeof(iid));i++;
		if (iid.Name)
		{
			printf("#%d ", i);
			print_string("Import module name: ", pe_file, iid.Name + delta_std_import_offset);
			printf("\n\n");

			printf("#%d DWORD ImgImpDscr.DUMMYUNIONNAME.Characteristics: 0x%.8lX\n", i, iid.Characteristics);
			printf("#%d DWORD ImgImpDscr.DUMMYUNIONNAME.OriginalFirstThunk: 0x%.8lX\n", i, iid.OriginalFirstThunk);
			printf("#%d DWORD ImgImpDscr.TimeDateStamp: 0x%.8lX %s\n", i, iid.TimeDateStamp, ctime((time_t*)&(iid.TimeDateStamp)));
			printf("#%d DWORD ImgImpDscr.ForwarderChain: 0x%.8lX\n", i, iid.ForwarderChain);
			printf("#%d DWORD ImgImpDscr.Name: 0x%.8lX\n", i, iid.Name);
			printf("#%d DWORD ImgImpDscr.FirstThunk: 0x%.8lX\n\n", i, iid.FirstThunk);
			if (flag)
			{
				WORD hint;
				DWORD function_name_offset;
				int j = 0;
				do
				{
					lseek(pe_file, iid.FirstThunk + delta_std_import_offset + j * sizeof(function_name_offset), SEEK_SET);
					read(pe_file, &function_name_offset, sizeof(function_name_offset));

					if (function_name_offset)
					{
						lseek(pe_file, function_name_offset + delta_std_import_offset, SEEK_SET);
						if (function_name_offset & 0x80000000)
							printf("#%d.%d ordinal/address : 0x%.8lX 0x%.8lX\n", i, j, function_name_offset & (~0x80000000), iid.FirstThunk + j * sizeof(iid.FirstThunk));
						else
						{
							read(pe_file, &hint, sizeof(hint));
							printf("#%d.%d ", i, j);
							print_string("Function name/Hint/Address: ", pe_file, function_name_offset + delta_std_import_offset + sizeof(hint));
							printf(" 0x%.4X ", hint);
							printf("0x%.8lX\n", iid.FirstThunk + j * sizeof(iid.FirstThunk));
						}
						j++;
					}
				} while (function_name_offset);
				printf("\n");
			}
			lseek(pe_file, istdid_file_offset + i * sizeof(iid), SEEK_SET);
		}
	} while (iid.Name);
}

void print_bound_import_metadata_and_tables(int pe_file, PIMAGE_SECTION_HEADER pS,
	int num_of_sections, DWORD ibid_v_offset,
	DWORD istdid_size, int flag)
{
	int i;
	int bound_import_section;
	int delta_bound_import_offset;
	int ibid_file_offset = 0;
	IMAGE_BOUND_IMPORT_DESCRIPTOR ibid;

	for (i = 0;i < num_of_sections;i++)
		if (ibid_v_offset >= pS[i].VirtualAddress &&
			ibid_v_offset <= pS[i].VirtualAddress + pS[i].Misc.VirtualSize) break;

	bound_import_section = i;
	printf("\nBound import section: #%d\n\n", bound_import_section);

	delta_bound_import_offset = pS[bound_import_section].PointerToRawData - pS[bound_import_section].VirtualAddress;
	printf("-delta standard import offset: 0x%.8X\n\n", -delta_bound_import_offset);

	ibid_file_offset = ibid_v_offset; //+ delta_bound_import_offset;	

	lseek(pe_file, ibid_file_offset, SEEK_SET);
	i = 0;

	do
	{
		//lseek(pe_file,ibid_file_offset+i*sizeof(ibid), SEEK_SET);
		read(pe_file, &ibid, sizeof(ibid));i++;
		if (ibid.OffsetModuleName)
		{
			/*printf("#%d ",i);
			print_string("Bound import module name: ", pe_file, ibid.OffsetModuleName+delta_bound_import_offset);
			printf("\n\n");*/
			printf("#%d DWORD ImgBoundImpDescr.TimeDateStamp: 0x%.8lX (%s)\n", i, ibid.TimeDateStamp, ctime((time_t*)&(ibid.TimeDateStamp)));
			printf("#%d WORD ImgBoundImpDescr.OffsetModuleName: 0x%.4X\n", i, ibid.OffsetModuleName);

		}

	} while (ibid.OffsetModuleName);

}

char* usage_msg = "\
peview <filename> [options]\n\
-h  - print pe headers\n\
-s  - print pe sections\n\
-e1 - print export header\n\
-e2 - print export tables (use with -e1 only)\n\
-i1 - print std import header\n\
-i2 - print std import tables (use with -i1 only)\n\
-b1 - print bound import header\n\
-b2 - print bound import tables (use with -b1 only)\n";

int main(int argc, char* argv[])
{

	int i = 0;
	int wpe_file = 0;

	IMAGE_NT_HEADERS32 inth32;
	DWORD e_lfanew = 0;

	PIMAGE_SECTION_HEADER pish;
	int pish_offset = 0;
	int ied_virtual_offset = 0;
	int istdid_virtual_offset = 0;
	int ibid_virtual_offset = 0;

	char* wpe_filename;

	int fl_ph = 0;
	int fl_ps = 0;
	int fl_pe1 = 0;
	int fl_pe2 = 0;
	int fl_pi1 = 0;
	int fl_pi2 = 0;
	int fl_pb1 = 0;
	int fl_pb2 = 0;

	if (argc > 1)
	{
		wpe_filename = argv[1];
		if (argc == 2) fl_ph = fl_ps = fl_pe1 = fl_pe2 = fl_pi1 = fl_pi2 = 1;
		else
		{
			for (i = 0;i < argc;i++)
			{
				if (!strcmp("-h", argv[i])) fl_ph = 1;
				else if (!strcmp("-s", argv[i])) fl_ps = 1;
				else if (!strcmp("-e1", argv[i])) fl_pe1 = 1;
				else if (!strcmp("-e2", argv[i])) fl_pe2 = 1;
				else if (!strcmp("-i1", argv[i])) fl_pi1 = 1;
				else if (!strcmp("-i2", argv[i])) fl_pi2 = 1;
				else if (!strcmp("-b1", argv[i])) fl_pb1 = 1;
				else if (!strcmp("-b2", argv[i])) fl_pb2 = 1;
			}
		}
	}

	else
	{
		printf("%s", usage_msg);
		return 0;
	}

	if ((0 > (wpe_file = open(wpe_filename, O_RDONLY | O_BINARY))))
	{
		printf("open(wpe_filename): can't open file %s\n", wpe_filename);
		return -1;
	}

	if (0x3c != lseek(wpe_file, 0x3c, SEEK_SET))
	{
		printf("lseek(0x3c): %s is not a PE-file\n", wpe_filename);
		if (close(wpe_file)) return -3;
		return -2;
	}

	if (sizeof(DWORD) != read(wpe_file, &e_lfanew, sizeof(DWORD)))
	{
		printf("read(e_lfanew): %s is not a PE-file\n", wpe_filename);
		if (close(wpe_file)) return -3;
		return -2;
	}

	printf("%s:\n\n", wpe_filename);
	printf("DWORD e_lfanew: 0x%.8lX  (%ld)\n\n", e_lfanew, e_lfanew);

	if (e_lfanew != lseek(wpe_file, e_lfanew, SEEK_SET))
	{
		printf("lseek(e_lfanew): %s is not a PE-file\n", wpe_filename);
		if (close(wpe_file)) return -3;
		return -2;
	}

	if (sizeof(inth32) != read(wpe_file, &inth32, sizeof(inth32)))
	{
		printf("read(Image_NT_Headers): %s is not a PE-file\n", wpe_filename);
		if (close(wpe_file)) return -3;
		return -2;
	}

	if (fl_ph) { if (print_image_nt_headers(&inth32)) return -3; }

	pish = (PIMAGE_SECTION_HEADER)malloc(inth32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	pish_offset = e_lfanew + sizeof(inth32);

	lseek(wpe_file, pish_offset, SEEK_SET);
	read(wpe_file, pish, inth32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	if (fl_ps)  print_image_section_headers(pish, inth32.FileHeader.NumberOfSections);

	ied_virtual_offset = inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (fl_pe1) if (ied_virtual_offset)
		print_export_metadata_and_tables(wpe_file,
			pish,
			inth32.FileHeader.NumberOfSections,
			ied_virtual_offset,
			inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, fl_pe2);

	istdid_virtual_offset = inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (fl_pi1) if (istdid_virtual_offset)
		print_std_import_metadata_and_tables(wpe_file,
			pish,
			inth32.FileHeader.NumberOfSections,
			istdid_virtual_offset,
			inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, fl_pi2);

	ibid_virtual_offset = inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;

	if (fl_pb1) if (ibid_virtual_offset)
		print_bound_import_metadata_and_tables(wpe_file,
			pish,
			inth32.FileHeader.NumberOfSections,
			istdid_virtual_offset,
			inth32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size, fl_pb2);


	free(pish);
	if (close(wpe_file)) return -4;

	return 0;
}
