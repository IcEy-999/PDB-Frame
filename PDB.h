#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include<Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")




class PDB {

	typedef struct _PdbInfo
	{
		DWORD	Signature;
		GUID	Guid;
		DWORD	Age;
		char	PdbFileName[1];
	}PdbInfo,*PPdbInfo;


	char PDBDownloadPath[MAX_PATH];		//Pdb下载，加载路径
	char ImagePath[MAX_PATH];			//镜像路径
	char ImageName[MAX_PATH];			//镜像名称
	char SymbolServerUrl[1024];			//Pdb 下载服务器


	PBYTE Image = NULL;			//镜像读到内存的基址
	HANDLE PDBProcessHandle;	//进程句柄
	DWORD64 PDBHandle;			//符号句柄
	DWORD64 NtoskrnlBase;		//nt内核基址

	BOOLEAN Read_Image();
	BOOLEAN Get_Pdb();
	
public:
	PDB(const char* EXEPath);

	BOOLEAN Load_Pdb();

	BOOLEAN GetSymOffset(IN PCWCH SymName,IN OUT PULONG64 POffset);

	BOOLEAN GetMembersOffsetFromStruct(IN PCWCH StructName, IN PCWCH MembersName, IN OUT PULONG64 POffset);

};