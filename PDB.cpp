#include"PDB.h"

BOOLEAN PDB::Read_Image() {
	BOOLEAN RC = FALSE;
	HANDLE Ntoskrnl_H = CreateFileA(ImagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);//载入文件
	if (Ntoskrnl_H == INVALID_HANDLE_VALUE)//是否成功载入文件
		return RC;
	char rdos[sizeof(IMAGE_DOS_HEADER)];//临时dos指针空间
	char rpe[sizeof(IMAGE_NT_HEADERS)];//临时NT空间
	DWORD NumberOfBytesRW = 0;
	if (ReadFile(Ntoskrnl_H, rdos, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRW, NULL) == FALSE)
		return RC;
	PIMAGE_DOS_HEADER rdoshead = (PIMAGE_DOS_HEADER)rdos;//DOS头指针（临时）
	SetFilePointer(Ntoskrnl_H, rdoshead->e_lfanew, NULL, FILE_BEGIN);//下一次读PE头
	if (ReadFile(Ntoskrnl_H, rpe, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRW, NULL) == FALSE)
		return RC;
	PIMAGE_NT_HEADERS rpehead = (PIMAGE_NT_HEADERS)rpe;
	Image = (PBYTE)malloc(rpehead->OptionalHeader.SizeOfImage);
	if (Image == NULL)
		return RC;
	SetFilePointer(Ntoskrnl_H, 0, NULL, FILE_BEGIN);//下一次读PE头
	if (ReadFile(Ntoskrnl_H, Image, rpehead->OptionalHeader.SizeOfHeaders, &NumberOfBytesRW, NULL) == FALSE)
		return RC;
	rdoshead = (PIMAGE_DOS_HEADER)Image;
	rpehead = (PIMAGE_NT_HEADERS)(rdoshead->e_lfanew + Image);


	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(rpehead);//取区段信息
	for (int i = 0; i < rpehead->FileHeader.NumberOfSections; i++, pSectionHeader++)//读区段数据,模仿镜像加载
	{
		SetFilePointer(Ntoskrnl_H, pSectionHeader->PointerToRawData, NULL, FILE_BEGIN);//设置下次读取地址
		//ALIGN(sectionsize, sectionalign);//对齐读取大小
		if (ReadFile(Ntoskrnl_H, Image + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData, &NumberOfBytesRW, NULL) == FALSE)
			return RC;
	}
	RC = TRUE;
	return RC;
}

//get pdb in Current Directory
BOOLEAN PDB::Get_Pdb()
{
	BOOLEAN RC = FALSE;
	if (PDBDownloadPath[strlen(PDBDownloadPath) - 1] != '\\')
	{
		strcat(PDBDownloadPath, "\\");
	}
	// get pdb info from debug info directory
	if (!Read_Image())//读文件到内存
		return RC;
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)Image;
	IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(Image + pDos->e_lfanew);
	IMAGE_FILE_HEADER* pFile = &pNT->FileHeader;
	IMAGE_OPTIONAL_HEADER64* pOpt64 = (IMAGE_OPTIONAL_HEADER64*)(&pNT->OptionalHeader);

	IMAGE_DATA_DIRECTORY* pDataDir = nullptr;
	pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(Image + pDataDir->VirtualAddress);
	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		// invalid debug dir
		free(Image);
		return RC;
		
	}
	PPdbInfo pdb_info = (PdbInfo*)(Image + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		// invalid debug dir
		free(Image);
		return RC;
	}

	// sometimes pdb_info->PdbFileName is a abs path, sometimes is just a base name.
	// In first case, we have to calc its base name.
	strcat(PDBDownloadPath, pdb_info->PdbFileName);//get pdb name

	// download pdb

	//判断pdb是否存在
	WIN32_FIND_DATAA wfd;
	HANDLE hFind = FindFirstFileA(PDBDownloadPath, &wfd);
	if (INVALID_HANDLE_VALUE != hFind)
	{
		//pdb已经存在，不需要下载
		free(Image);
		RC = TRUE;
		return RC;
	}

	wchar_t w_GUID[100] = { 0 };
	if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
	{
		free(Image);
		return RC;
	}
	char a_GUID[100]{ 0 };//get debug_guid
	size_t l_GUID = 0;
	if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID)
	{
		free(Image);
		return RC;
	}

	char guid_filtered[256] = { 0 };
	for (UINT i = 0; i != l_GUID; ++i)
	{
		if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') || (a_GUID[i] >= 'a' && a_GUID[i] <= 'f'))
		{
			guid_filtered[strlen(guid_filtered)] = a_GUID[i];
		}
	}

	char age[3] = { 0 };
	_itoa_s(pdb_info->Age, age, 10);

	// url
	char url[1024] = { 0 };
	strcpy(url, SymbolServerUrl);
	strcat(url, pdb_info->PdbFileName);
	url[strlen(url)] = '/';
	strcat(url, guid_filtered);
	strcat(url, age);
	url[strlen(url)] = '/';
	strcat(url, pdb_info->PdbFileName);

	// download
	HRESULT hr = URLDownloadToFileA(NULL, url, PDBDownloadPath, NULL, NULL);
	if (FAILED(hr))
	{
		free(Image);
		return RC;
	}
	RC = TRUE;
EXIT:
	free(Image);
	return RC;
}

//load pdb file and exe
BOOLEAN PDB::Load_Pdb() {
	DWORD32 error = 0;
	BOOLEAN RC = FALSE;
	if (!Get_Pdb())
	{
		printf("PDB download error!\n");
		return RC;
	}
	PDBProcessHandle = OpenProcess(FILE_ALL_ACCESS, 0, GetCurrentProcessId());

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	if (!SymInitialize(PDBProcessHandle, PDBDownloadPath, TRUE))
	{
		// SymInitialize failed
		error = GetLastError();
		printf("SymInitialize returned error : %d\n", error);
		return RC;
	}
	//TCHAR  szImageName[MAX_PATH] = TEXT("foo.dll");
	DWORD64 dwBaseAddr = 0;

	PDBHandle = SymLoadModuleEx(PDBProcessHandle,    // target process 
		NULL,        // handle to image - not used
		ImagePath, // name of image file
		NULL,        // name of module - not required
		dwBaseAddr,  // base address - not required
		0,           // size of image - not required
		NULL,        // MODLOAD_DATA used for special cases 
		0);        // flags - not required

	if (PDBHandle == NULL)
	{
		error = GetLastError();
		printf("SymLoadModuleEx error : %d\n", error);
		return RC;
	}
	RC = TRUE;
	return RC;
}

//get Sym Address in kernel
BOOLEAN PDB::GetSymOffset(IN PCWCH SymName, IN OUT PULONG64 POffset) {
	BOOLEAN RC = FALSE;
	PSYMBOL_INFOW Information = new SYMBOL_INFOW();
	if (!SymFromNameW(PDBProcessHandle, SymName, Information)) {
		delete Information;
		return RC;
	}
	*POffset =  Information->Address;
	RC = TRUE;
	delete Information;
	return RC;
}

//get Struct Members offset
BOOLEAN PDB::GetMembersOffsetFromStruct(IN PCWCH StructName, IN PCWCH MembersName, IN OUT PULONG64 POffset) {
	BOOLEAN RC = FALSE;
	PWCHAR pNameW = NULL;//名字
	PSYMBOL_INFOW Information = new SYMBOL_INFOW;
	ULONG ElementCount = 0;//结构成员个数
	memset(Information, 0, sizeof(SYMBOL_INFOW));

	if (!SymGetTypeFromNameW(PDBProcessHandle, PDBHandle, StructName, Information)) {
		delete Information;
		return RC;
	}
		

	//获取结构成员数
	if (!SymGetTypeInfo(PDBProcessHandle, PDBHandle, Information->TypeIndex, TI_GET_CHILDRENCOUNT, &ElementCount)) {
		delete Information;
		return RC;
	}
	ULONG64 ElementCount64 = ElementCount;
	DWORD dwSizeFind = sizeof(ULONG64) * (2 + ElementCount64);
	TI_FINDCHILDREN_PARAMS* pCP = new TI_FINDCHILDREN_PARAMS[dwSizeFind]();
	pCP->Count = ElementCount;

	if (!SymGetTypeInfo(PDBProcessHandle, PDBHandle, Information->TypeIndex, TI_FINDCHILDREN, pCP)) {
		delete Information, pCP;
		return RC;
	}

	//获取成员信息
	for (int i = 0; i < ElementCount; ++i)
	{
		DWORD dwOffset = 0;

		//名字
		if (!SymGetTypeInfo(PDBProcessHandle, PDBHandle, pCP->ChildId[i], TI_GET_SYMNAME, &pNameW)) {
			delete Information, pCP;
			return RC;
		}
		if (lstrcmpW(pNameW, MembersName) == 0)
		{
			if (!SymGetTypeInfo(PDBProcessHandle, PDBHandle, pCP->ChildId[i], TI_GET_OFFSET, &dwOffset)) {
				LocalFree(pNameW);
				delete Information, pCP;
				return RC;
			}
			LocalFree(pNameW);
			delete Information, pCP;
			
			*POffset = dwOffset;
			RC = TRUE;
			return RC;
		}
		LocalFree(pNameW);
	}
}

//imageName and ImagePath
PDB::PDB(const char* EXEPath) {
	const char* EXEName = NULL;
	char Current_Path[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, Current_Path);
	int len = strlen(EXEPath);
	for (int i = len - 1; i > 0; i--) {
		if (EXEPath[i] == '\\') {
			EXEName = &EXEPath[i + 1];
			break;
		}
	}
	strcpy(ImageName, EXEName);
	//strcpy(szDllDir, ImagePath);
	//szDllDir[GetBaseName(ImagePath) - ImagePath] = NULL;

	strcpy(SymbolServerUrl, "https://msdl.microsoft.com/download/symbols/");//设置pdb服务器

	strcpy(ImagePath, (const char*)EXEPath);//ntoskrnl.exe路径

	strcpy(PDBDownloadPath, Current_Path);//get pdb path
}