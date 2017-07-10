// EXEProtect.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PE_Parse.h"
#define ProtectedPE "C://testShell//a.exe"

typedef struct _ChildProcessInfo {
DWORD dwBaseAddress; 
DWORD dwReserve; 
} CHILDPROCESS, *PCHILDPROCESS;


PE_Parse* p_gPE;
PE_Parse* p_gPE_Main;
CONTEXT contx;  //真正需要运行的程序线程上下文
HMODULE hModule=NULL;    //整个程序的PimageBase
PROCESS_INFORMATION ie_pi;    //傀儡程序信息

//验证是否有宿主PE在节表中
BOOL IsPEinSection()
{
	if((p_gPE->pPEHeader->NumberOfSections==5))
	{
		return FALSE;
	}
	return TRUE;
}
//读取主模块的数据
BOOL GetPEData(OUT LPVOID* pPE_Main)
{
	LPVOID pTemp=NULL;
	DWORD SectionNum=p_gPE->pPEHeader->NumberOfSections;
	DWORD Main_size=p_gPE->pSectionHeader[SectionNum-1].SizeOfRawData;
	DWORD Main_FOA=p_gPE->pSectionHeader[SectionNum-1].PointerToRawData;
	printf("主模块信息如下：\n 模块名：%s |文件偏移：%x|大小:%x\n",p_gPE->pSectionHeader[SectionNum-1].Name,Main_FOA,Main_size);
	//分配主模块的堆内存
	pTemp=malloc(Main_size);
	memset(pTemp,0,Main_size);
	::memcpy(pTemp,(LPVOID)((DWORD)p_gPE->pFileBuffer+Main_FOA),Main_size);
	*pPE_Main=pTemp;
	pTemp=NULL;

	return TRUE;
}


BOOL UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr)   
{   
    typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);   
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL; 

    BOOL res = FALSE;   
    HMODULE m = LoadLibrary("ntdll.dll");   
    if(m)
	{   
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");   
        if(ZwUnmapViewOfSection)   
            res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);   
        FreeLibrary(m);   
    }   
    return res; 
}

BOOL CreateSuspendProcess()
{
	DWORD dwWrite=0;
	STARTUPINFO ie_si = {0};   														
	ie_si.cb = sizeof(ie_si);							
	LPVOID lpVirtual =NULL;
	DWORD * PPEB;
	CHILDPROCESS stChildProcess; 
	//以挂起的方式创建进程												
	CreateProcess(							
		NULL,                    // name of executable module						
		ProtectedPE,                // command line string						
		NULL, 					 // SD	
		NULL,  		             // SD				
		FALSE,                   // handle inheritance option						
		CREATE_SUSPENDED,     	 // creation flags  					
		NULL,                    // new environment block						
		NULL,                    // current directory name						
		&ie_si,                  // startup information						
		&ie_pi                   // process information						
		);		
	
	contx.ContextFlags = CONTEXT_FULL;  							
								
	GetThreadContext(ie_pi.hThread, &contx);

	//获取入口点
	DWORD dwEntryPoint=contx.Eax;
	//获取ImageBase
	//char* baseAddress = (CHAR *) contx.Ebx+8;						
							
	//DWORD dwBaseAddr=0;					
							
	//ReadProcessMemory(ie_pi.hProcess,baseAddress,&dwBaseAddr,4,NULL);	
	PPEB=(DWORD*)contx.Ebx;
	::ReadProcessMemory(ie_pi.hProcess,&PPEB[2],&(stChildProcess.dwBaseAddress),sizeof(DWORD),NULL);

	//卸载外壳程序
	if(!UnloadShell(ie_pi.hProcess,stChildProcess.dwBaseAddress))
	{
		return FALSE;
	}
	//重新分配内存
	lpVirtual=::VirtualAllocEx(
		ie_pi.hProcess,
		(LPVOID)(p_gPE_Main->pOptionalHeader->ImageBase),
		p_gPE_Main->pOptionalHeader->SizeOfImage,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(lpVirtual)
	{
		printf("分配傀儡进程内存成功！\n");
		//拉伸PE_Main到傀儡进程
		LPVOID PEImageBuffer=NULL;    //记得要释放内存
		if(p_gPE_Main->CopyFromFileBufferToImageBuffer(&PEImageBuffer)<0)
		{
			return FALSE;
		}
		//writeprocessMemory在傀儡进程分配的内存中把主模块加载进去
		if(!::WriteProcessMemory(
			ie_pi.hProcess,
			lpVirtual,
			PEImageBuffer,
			p_gPE_Main->pOptionalHeader->SizeOfImage,
			&dwWrite))
		{
			printf("imagebuffer写入失败\n");
			free(PEImageBuffer);
			PEImageBuffer=NULL;
			return FALSE;
		}
		

	}else
	{
		printf("分配傀儡进程内存失败！\n");
		//判断有没有重定位表，如果有的话，就在任意位置申请空间，然后PE文件拉伸、复制、修复重定位表
		//if(p_gPE_Main->pOptionalHeader->DataDirectory[]){}
		return FALSE;
	}

	//重写CONTX
	PPEB=(DWORD*)contx.Ebx;
	::WriteProcessMemory(
		ie_pi.hProcess,
		&PPEB[2],
		&lpVirtual,
		sizeof(DWORD),
		NULL
		);
	if((DWORD)lpVirtual==stChildProcess.dwBaseAddress)
	{
		printf("分配的进程空间基地址与受保护的程序imagebase一致\n");
		contx.Eax=(DWORD)p_gPE_Main->pOptionalHeader->ImageBase+p_gPE_Main->pOptionalHeader->AddressOfEntryPoint;
	}else{
		printf("分配的进程空间基地址与受保护的程序imagebase不一致\n");
		contx.Eax=(DWORD)lpVirtual+p_gPE_Main->pOptionalHeader->AddressOfEntryPoint;
	}
	
	::SetThreadContext(ie_pi.hThread,&contx);
	::ResumeThread(ie_pi.hThread);
	printf("傀儡进程已经被主模块装载\n");
	return TRUE;
		
}


int main(int argc, char* argv[])
{
	LPVOID P_Main=NULL;
	hModule=::GetModuleHandle(NULL);
	if(hModule==NULL)
	{
		return 1;
	}
	p_gPE=new PE_Parse(ProtectedPE);
	if(!IsPEinSection())
	{
		printf("宿主程序还未加载，请用PE工具注入程序！");
		return 2;
	}
	//得到主模块数据
	GetPEData(&P_Main);
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)(P_Main);
	PIMAGE_NT_HEADERS pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)(P_Main)+pDosHeader->e_lfanew);

	p_gPE_Main=new PE_Parse(P_Main);
	//解密（省去）
	//以挂起形式创建进程,并将紫禁城掏空，重新分配主模块进程
	if(!CreateSuspendProcess())
	{
		printf("创建紫禁城失败！");
		return 3;
	}
	//运行主模块
//	RunMainModule();
	delete p_gPE;
	delete p_gPE_Main;
	return 0;
}

