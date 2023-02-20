# ReadMe

提供镜像文件路径，自动下载PDB，然后加载PDB。

Provide the image file path, automatically download the PDB, and then load the PDB.



###### 导出函数：

```c++
//通过符号名获取偏移 
BOOLEAN GetSymOffset(IN PCWCH SymName,IN OUT PULONG64 POffset);

//通过结构名和结构成员名获取偏移
BOOLEAN GetMembersOffsetFromStruct(IN PCWCH StructName, IN PCWCH MembersName, IN OUT PULONG64 POffset);
```



###### demo：

```c++
#include"PDB.h"
#define Ntoskrnl_Path   "C:\\Windows\\System32\\ntoskrnl.exe"

int main() {
	PDB Task(Ntoskrnl_Path);
	Task.Load_Pdb();
	ULONG64 off = 0,off2 = 0;
	Task.GetSymOffset(L"KdDebuggerEnabled", &off);
	Task.GetMembersOffsetFromStruct(L"_EPROCESS", L"ImageFileName", &off2);
	system("pause");
}
```

