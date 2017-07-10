// PE_Parse.cpp: implementation of the PE_Parse class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "PE_Parse.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

PE_Parse::PE_Parse(LPSTR PstrPath)
{
	this->PstrPath=PstrPath;
	DWORD retN=ReadFileToBuffer(this->PstrPath,&(this->pFileBuffer));
	if(!retN){
		printf("��ȡPE�ļ�����");
		return;
	}
	getHeaders();
}
PE_Parse::PE_Parse(LPVOID pFileBuffer)
{
	this->pFileBuffer=pFileBuffer;
	getHeaders();
}

void PE_Parse::getHeaders()
{
	this->pDosHeader=(PIMAGE_DOS_HEADER)(this->pFileBuffer);
	this->pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew);
	this->pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4);
	this->pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	this->pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
}
//���ļ���ȡ���ļ���������
DWORD PE_Parse::ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

	FILE* pFile=NULL;
	DWORD fileSize=0;
	LPVOID pTempFileBuffer=NULL; 


	pFile=fopen(FilePath,"rb");

	if(!pFile){
		printf("�޷��򿪸��ļ�\n");
		return 0;
	}
	
	fseek(pFile,0,SEEK_END);

	fileSize=ftell(pFile);
	this->filelen=fileSize;
	
	fseek(pFile,0,SEEK_SET);

	//�����ڴ�ռ�
	pTempFileBuffer=malloc(fileSize);
	
	//ǿ����Ŀռ��ʼ��Ϊ0
	memset(pTempFileBuffer,0,fileSize);
	if(!pTempFileBuffer){
		printf("����ռ�ʧ��\n");
		fclose(pFile);
		return 0;
	}
	
	int n=fread(pTempFileBuffer,fileSize,1,pFile);

	if(!n){
		printf("��ȡ�ļ�ʧ��\n");
		fclose(pFile);
		free(pTempFileBuffer);
		return 0;
	}

	*pFileBuffer=pTempFileBuffer;
	pTempFileBuffer=NULL;


	return fileSize;
}

PE_Parse::~PE_Parse()
{

	//�ͷŵ����ص�PE file_buffer
	free(this->pFileBuffer);
	this->pFileBuffer=NULL;
}


DWORD PE_Parse::RVAToFOA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	//�ڴ�����С
	DWORD dwMemorAli=pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pNT->FileHeader.SizeOfOptionalHeader);
	//�������нڵ���ʼ�����ַƫ��ֵ
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		//sizeofrawdata���ļ������Ĵ�С�������С�����ļ����쵽�ڴ���ʱҪ�����Ĵ�С
		DWORD dwBlockCount=pSection[i].SizeOfRawData/dwMemorAli;
		dwBlockCount+=pSection[i].SizeOfRawData%dwMemorAli?1:0;
		DWORD dwBeginVA=pSection[i].VirtualAddress;
		DWORD dwEndVA=pSection[i].VirtualAddress+dwBlockCount*dwMemorAli;
		//�ж����stRVA��ĳ��������
		if(stRVA>=dwBeginVA&&stRVA<dwEndVA){
			dwDiffer=stRVA-dwBeginVA;
			return pSection[i].PointerToRawData+dwDiffer;

		}else if(stRVA<dwBeginVA){//��λ�����ļ�ͷ�У�ֱ�ӷ��ص�ַ
			
			return stRVA;
		}

	}
	return 0;
}

DWORD PE_Parse::FOAToRVA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+IMAGE_SIZEOF_NT_OPTIONAL32_HEADER);
	//�������нڵ���ʼ�����ַƫ��ֵ
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		DWORD FileBeginVA=pSection[i].PointerToRawData;
		DWORD FileEndVA=pSection[i].PointerToRawData+pSection[i].SizeOfRawData;
		//printf("FileBeginVA:%x   FileEndVA:%x  you:%x\n",FileBeginVA,FileEndVA,stRVA);
		//�ж����stRVA��ĳ��������
		if(stRVA>=FileBeginVA&&stRVA<FileEndVA){
			dwDiffer=stRVA-FileBeginVA;
			return pSection[i].VirtualAddress+dwDiffer;

		}else if(stRVA<FileBeginVA){//��λ�����ļ�ͷ�У�ֱ�ӷ��ص�ַ
		
			return stRVA;
		}

	}
	return 0;
}

//��pe�ļ�����Ϊ�ڴ���ʽ
DWORD PE_Parse::CopyFromFileBufferToImageBuffer(OUT LPVOID* pImageBuffer){

	//����SIZE_OF_IMAGE�������ڴ滺�����Ĵ�С����Ȼÿһ��Ӧ�ó����������϶�ӵ�ж�����4GB�����ڴ棬���ǻ��Ǹ���SIZE FOF IMAGE�������ڴ��С
	LPVOID pTempImageBuffer=NULL;
	pTempImageBuffer=malloc(pOptionalHeader->SizeOfImage);
	printf("�ļ���sizeofImageΪ%x\n",pOptionalHeader->SizeOfImage);
	if(pTempImageBuffer==NULL){
		printf("�����ڴ澵���ļ�ʧ��\n");
		return -1;
	}

	memset(pTempImageBuffer,0,pOptionalHeader->SizeOfImage);

	//��ʼ���ļ����������������񻺳�����  1����һ���������е�ͷ���������񻺳����� DosHeader+NTHeader+SectionHeader
	memcpy(pTempImageBuffer,pFileBuffer,pOptionalHeader->SizeOfHeaders);
	
	int i;
	PIMAGE_SECTION_HEADER pTempSectionHeader=pSectionHeader;

	for(i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
		memcpy(
			(PVOID)((DWORD)pTempImageBuffer+pTempSectionHeader->VirtualAddress),
			(void*)((DWORD)pDosHeader+pTempSectionHeader->PointerToRawData),
			pTempSectionHeader->SizeOfRawData);
	}

	*pImageBuffer=pTempImageBuffer;
	pTempImageBuffer=NULL;

	return pOptionalHeader->SizeOfImage;

}

