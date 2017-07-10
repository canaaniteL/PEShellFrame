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
CONTEXT contx;  //������Ҫ���еĳ����߳�������
HMODULE hModule=NULL;    //���������PimageBase
PROCESS_INFORMATION ie_pi;    //���ܳ�����Ϣ

//��֤�Ƿ�������PE�ڽڱ���
BOOL IsPEinSection()
{
	if((p_gPE->pPEHeader->NumberOfSections==5))
	{
		return FALSE;
	}
	return TRUE;
}
//��ȡ��ģ�������
BOOL GetPEData(OUT LPVOID* pPE_Main)
{
	LPVOID pTemp=NULL;
	DWORD SectionNum=p_gPE->pPEHeader->NumberOfSections;
	DWORD Main_size=p_gPE->pSectionHeader[SectionNum-1].SizeOfRawData;
	DWORD Main_FOA=p_gPE->pSectionHeader[SectionNum-1].PointerToRawData;
	printf("��ģ����Ϣ���£�\n ģ������%s |�ļ�ƫ�ƣ�%x|��С:%x\n",p_gPE->pSectionHeader[SectionNum-1].Name,Main_FOA,Main_size);
	//������ģ��Ķ��ڴ�
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
	//�Թ���ķ�ʽ��������												
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

	//��ȡ��ڵ�
	DWORD dwEntryPoint=contx.Eax;
	//��ȡImageBase
	//char* baseAddress = (CHAR *) contx.Ebx+8;						
							
	//DWORD dwBaseAddr=0;					
							
	//ReadProcessMemory(ie_pi.hProcess,baseAddress,&dwBaseAddr,4,NULL);	
	PPEB=(DWORD*)contx.Ebx;
	::ReadProcessMemory(ie_pi.hProcess,&PPEB[2],&(stChildProcess.dwBaseAddress),sizeof(DWORD),NULL);

	//ж����ǳ���
	if(!UnloadShell(ie_pi.hProcess,stChildProcess.dwBaseAddress))
	{
		return FALSE;
	}
	//���·����ڴ�
	lpVirtual=::VirtualAllocEx(
		ie_pi.hProcess,
		(LPVOID)(p_gPE_Main->pOptionalHeader->ImageBase),
		p_gPE_Main->pOptionalHeader->SizeOfImage,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(lpVirtual)
	{
		printf("������ܽ����ڴ�ɹ���\n");
		//����PE_Main�����ܽ���
		LPVOID PEImageBuffer=NULL;    //�ǵ�Ҫ�ͷ��ڴ�
		if(p_gPE_Main->CopyFromFileBufferToImageBuffer(&PEImageBuffer)<0)
		{
			return FALSE;
		}
		//writeprocessMemory�ڿ��ܽ��̷�����ڴ��а���ģ����ؽ�ȥ
		if(!::WriteProcessMemory(
			ie_pi.hProcess,
			lpVirtual,
			PEImageBuffer,
			p_gPE_Main->pOptionalHeader->SizeOfImage,
			&dwWrite))
		{
			printf("imagebufferд��ʧ��\n");
			free(PEImageBuffer);
			PEImageBuffer=NULL;
			return FALSE;
		}
		

	}else
	{
		printf("������ܽ����ڴ�ʧ�ܣ�\n");
		//�ж���û���ض�λ������еĻ�����������λ������ռ䣬Ȼ��PE�ļ����졢���ơ��޸��ض�λ��
		//if(p_gPE_Main->pOptionalHeader->DataDirectory[]){}
		return FALSE;
	}

	//��дCONTX
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
		printf("����Ľ��̿ռ����ַ���ܱ����ĳ���imagebaseһ��\n");
		contx.Eax=(DWORD)p_gPE_Main->pOptionalHeader->ImageBase+p_gPE_Main->pOptionalHeader->AddressOfEntryPoint;
	}else{
		printf("����Ľ��̿ռ����ַ���ܱ����ĳ���imagebase��һ��\n");
		contx.Eax=(DWORD)lpVirtual+p_gPE_Main->pOptionalHeader->AddressOfEntryPoint;
	}
	
	::SetThreadContext(ie_pi.hThread,&contx);
	::ResumeThread(ie_pi.hThread);
	printf("���ܽ����Ѿ�����ģ��װ��\n");
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
		printf("��������δ���أ�����PE����ע�����");
		return 2;
	}
	//�õ���ģ������
	GetPEData(&P_Main);
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)(P_Main);
	PIMAGE_NT_HEADERS pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)(P_Main)+pDosHeader->e_lfanew);

	p_gPE_Main=new PE_Parse(P_Main);
	//���ܣ�ʡȥ��
	//�Թ�����ʽ��������,�����Ͻ����Ϳգ����·�����ģ�����
	if(!CreateSuspendProcess())
	{
		printf("�����Ͻ���ʧ�ܣ�");
		return 3;
	}
	//������ģ��
//	RunMainModule();
	delete p_gPE;
	delete p_gPE_Main;
	return 0;
}

