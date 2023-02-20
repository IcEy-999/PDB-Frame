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


	char PDBDownloadPath[MAX_PATH];		//Pdb���أ�����·��
	char ImagePath[MAX_PATH];			//����·��
	char ImageName[MAX_PATH];			//��������
	char SymbolServerUrl[1024];			//Pdb ���ط�����


	PBYTE Image = NULL;			//��������ڴ�Ļ�ַ
	HANDLE PDBProcessHandle;	//���̾��
	DWORD64 PDBHandle;			//���ž��
	DWORD64 NtoskrnlBase;		//nt�ں˻�ַ

	BOOLEAN Read_Image();
	BOOLEAN Get_Pdb();
	
public:
	PDB(const char* EXEPath);

	BOOLEAN Load_Pdb();

	BOOLEAN GetSymOffset(IN PCWCH SymName,IN OUT PULONG64 POffset);

	BOOLEAN GetMembersOffsetFromStruct(IN PCWCH StructName, IN PCWCH MembersName, IN OUT PULONG64 POffset);

};