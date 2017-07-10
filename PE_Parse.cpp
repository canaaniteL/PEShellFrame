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
		printf("读取PE文件错误");
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
//将文件读取到文件缓冲区中
DWORD PE_Parse::ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

	FILE* pFile=NULL;
	DWORD fileSize=0;
	LPVOID pTempFileBuffer=NULL; 


	pFile=fopen(FilePath,"rb");

	if(!pFile){
		printf("无法打开该文件\n");
		return 0;
	}
	
	fseek(pFile,0,SEEK_END);

	fileSize=ftell(pFile);
	this->filelen=fileSize;
	
	fseek(pFile,0,SEEK_SET);

	//分配内存空间
	pTempFileBuffer=malloc(fileSize);
	
	//强申请的空间初始化为0
	memset(pTempFileBuffer,0,fileSize);
	if(!pTempFileBuffer){
		printf("申请空间失败\n");
		fclose(pFile);
		return 0;
	}
	
	int n=fread(pTempFileBuffer,fileSize,1,pFile);

	if(!n){
		printf("读取文件失败\n");
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

	//释放掉加载的PE file_buffer
	free(this->pFileBuffer);
	this->pFileBuffer=NULL;
}


DWORD PE_Parse::RVAToFOA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	//内存对齐大小
	DWORD dwMemorAli=pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pNT->FileHeader.SizeOfOptionalHeader);
	//距离命中节的起始虚拟地址偏移值
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		//sizeofrawdata是文件对齐后的大小，这个大小才是文件拉伸到内存中时要拷贝的大小
		DWORD dwBlockCount=pSection[i].SizeOfRawData/dwMemorAli;
		dwBlockCount+=pSection[i].SizeOfRawData%dwMemorAli?1:0;
		DWORD dwBeginVA=pSection[i].VirtualAddress;
		DWORD dwEndVA=pSection[i].VirtualAddress+dwBlockCount*dwMemorAli;
		//判断如果stRVA在某个区段中
		if(stRVA>=dwBeginVA&&stRVA<dwEndVA){
			dwDiffer=stRVA-dwBeginVA;
			return pSection[i].PointerToRawData+dwDiffer;

		}else if(stRVA<dwBeginVA){//该位置在文件头中，直接返回地址
			
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
	//距离命中节的起始虚拟地址偏移值
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		DWORD FileBeginVA=pSection[i].PointerToRawData;
		DWORD FileEndVA=pSection[i].PointerToRawData+pSection[i].SizeOfRawData;
		//printf("FileBeginVA:%x   FileEndVA:%x  you:%x\n",FileBeginVA,FileEndVA,stRVA);
		//判断如果stRVA在某个区段中
		if(stRVA>=FileBeginVA&&stRVA<FileEndVA){
			dwDiffer=stRVA-FileBeginVA;
			return pSection[i].VirtualAddress+dwDiffer;

		}else if(stRVA<FileBeginVA){//该位置在文件头中，直接返回地址
		
			return stRVA;
		}

	}
	return 0;
}

//将pe文件拉伸为内存样式
DWORD PE_Parse::CopyFromFileBufferToImageBuffer(OUT LPVOID* pImageBuffer){

	//根据SIZE_OF_IMAGE来分配内存缓冲区的大小，虽然每一个应用程序在理论上都拥有独立的4GB虚拟内存，但是还是根据SIZE FOF IMAGE来分配内存大小
	LPVOID pTempImageBuffer=NULL;
	pTempImageBuffer=malloc(pOptionalHeader->SizeOfImage);
	printf("文件的sizeofImage为%x\n",pOptionalHeader->SizeOfImage);
	if(pTempImageBuffer==NULL){
		printf("分配内存镜像文件失败\n");
		return -1;
	}

	memset(pTempImageBuffer,0,pOptionalHeader->SizeOfImage);

	//开始从文件缓冲区拷贝到镜像缓冲区中  1：第一步：将所有的头拷贝到镜像缓冲区中 DosHeader+NTHeader+SectionHeader
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

