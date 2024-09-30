# Project Summary

### Summary

**English:**

### Project Description

#### Overview
This project consists of multiple C++ files that together form a tool for encrypting and packing executable files (PE files) using the AES encryption algorithm. The primary goal is to enhance the security of executable files by encrypting their sections and packing them with a stub (a small piece of code) that decrypts and loads the original executable at runtime.

#### Key Components

1. **AES.cpp**
   - **Purpose**: Implements the AES encryption algorithm.
   - **Features**:
     - Defines the `AES` class with methods for encryption (`Cipher`) and decryption (`InvCipher`).
     - Includes methods for key expansion, byte substitution, row shifting, column mixing, and round key addition.
     - Supports both encryption and decryption of data blocks.

2. **CD-PACKER.cpp**
   - **Purpose**: Main entry point for the packing tool.
   - **Features**:
     - Opens and reads the target executable file.
     - Loads a stub DLL (`stub.dll`) which contains the decryption logic.
     - Performs initial checks to ensure the target file is suitable for packing.
     - Prepares the target file for encryption and packing.

3. **CPeFileOper.cpp**
   - **Purpose**: Provides functions for operating on PE (Portable Executable) files.
   - **Features**:
     - Functions to open, read, and save PE files.
     - Methods to retrieve various PE headers (DOS, NT, File, Optional).
     - Functions to add new sections to the PE file and align section sizes.
     - Methods to encrypt sections of the PE file using AES.
     - Functions to clear data directories and fix relocation entries.

4. **stub.cpp**
   - **Purpose**: Contains the stub code that will be injected into the packed executable.
   - **Features**:
     - The stub is a small piece of code that decrypts the original executable at runtime.
     - The stub is loaded from a DLL (`stub.dll`) and contains the necessary logic to decrypt and execute the original code.

#### Workflow

1. **Initialization**:
   - The `CD-PACKER.cpp` file initializes the `CPeFileOper` class to handle PE file operations.
   - It opens the target executable and loads the stub DLL.

2. **Pre-Packing Checks**:
   - The tool performs several checks to ensure the target file is suitable for packing, such as verifying the presence of a relocation table and checking for TLS (Thread Local Storage) tables.

3. **Encryption**:
   - The `CPeFileOper` class encrypts the sections of the target executable using the AES encryption algorithm.
   - The encryption key is stored in the stub configuration structure.

4. **Packing**:
   - The tool adds a new section to the target executable to store the encrypted data and the stub code.
   - It clears the data directories in the PE header to hide the original structure.

5. **Fixing Relocations**:
   - The tool fixes the relocation entries in the stub DLL to ensure it can be correctly loaded and executed at runtime.

6. **Saving the Packed File**:
   - The modified executable, now packed with the encrypted sections and the stub code, is saved to a new file.

#### Usage

- The tool is designed to be run from the command line, with the target executable specified as an argument.
- The packed executable will contain the encrypted sections and the stub code, which will decrypt and execute the original code at runtime.

#### Dependencies

- The project relies on the Windows API for file handling and memory management.
- The AES encryption algorithm is implemented in the `AES.cpp` file.
- The stub code is loaded from a DLL (`stub.dll`), which must be present in the same directory as the tool.

#### Security Considerations

- The tool enhances the security of executables by encrypting their sections, making it harder for attackers to reverse-engineer the code.
- The stub code, which is responsible for decrypting the original executable at runtime, is a critical component and should be protected to prevent tampering.

#### Future Enhancements

- Support for additional encryption algorithms.
- Integration with a GUI for easier use.
- Improved error handling and logging.
- Support for packing multiple files in a single operation.

This project provides a robust solution for enhancing the security of executable files by encrypting their sections and packing them with a stub that decrypts and loads the original code at runtime.

**Chinese:**

### 项目描述

#### 概述
本项目由多个C++文件组成，共同构成一个用于加密和打包可执行文件（PE文件）的工具，使用AES加密算法。主要目标是增强可执行文件的安全性，通过加密其节区并使用存根（一小段代码）在运行时解密和加载原始可执行文件。

#### 关键组件

1. **AES.cpp**
   - **目的**: 实现AES加密算法。
   - **功能**:
     - 定义了`AES`类，包含加密(`Cipher`)和解密(`InvCipher`)方法。
     - 包含密钥扩展、字节替换、行移位、列混合和轮密钥加法的方法。
     - 支持数据块的加密和解密。

2. **CD-PACKER.cpp**
   - **目的**: 打包工具的主入口点。
   - **功能**:
     - 打开并读取目标可执行文件。
     - 加载存根DLL(`stub.dll`)，其中包含解密逻辑。
     - 执行初始检查，确保目标文件适合打包。
     - 准备目标文件进行加密和打包。

3. **CPeFileOper.cpp**
   - **目的**: 提供操作PE（可移植可执行文件）文件的功能。
   - **功能**:
     - 打开、读取和保存PE文件的函数。
     - 获取各种PE头（DOS、NT、文件、可选）的方法。
     - 向PE文件添加新节区并调整节区大小的函数。
     - 使用AES加密PE文件节区的方法。
     - 清除数据目录和修复重定位条目的函数。

4. **stub.cpp**
   - **目的**: 包含将被注入到打包可执行文件中的存根代码。
   - **功能**:
     - 存根是一小段代码，在运行时解密原始可执行文件。
     - 存根从DLL(`stub.dll`)加载，并包含解密和执行原始代码所需的逻辑。

#### 工作流程

1. **初始化**:
   - `CD-PACKER.cpp`文件初始化`CPeFileOper`类以处理PE文件操作。
   - 打开目标可执行文件并加载存根DLL。

2. **打包前检查**:
   - 工具执行多项检查，确保目标文件适合打包，例如验证重定位表的存在并检查TLS（线程本地存储）表。

3. **加密**:
   - `CPeFileOper`类使用AES加密算法加密目标可执行文件的节区。
   - 加密密钥存储在存根配置结构中。

4. **打包**:
   - 工具向目标可执行文件添加新节区，以存储加密数据和存根代码。
   - 清除PE头中的数据目录以隐藏原始结构。

5. **修复重定位**:
   - 工具修复存根DLL中的重定位条目，以确保其在运行时能正确加载和执行。

6. **保存打包文件**:
   - 修改后的可执行文件，现在包含加密节区和存根代码，保存到新文件中。

#### 使用方法

- 该工具设计为从命令行运行，目标可执行文件作为参数指定。
- 打包后的可执行文件将包含加密节区和存根代码，在运行时解密并执行原始代码。

#### 依赖项

- 项目依赖Windows API进行文件处理和内存管理。
- AES加密算法在`AES.cpp`文件中实现。
- 存根代码从DLL(`stub.dll`)加载，该DLL必须与工具位于同一目录中。

#### 安全考虑

- 该工具通过加密可执行文件的节区来增强其安全性，使攻击者更难逆向工程代码。
- 存根代码负责在运行时解密原始可执行文件，是一个关键组件，应加以保护以防止篡改。

#### 未来增强

- 支持额外的加密算法。
- 与GUI集成以方便使用。
- 改进错误处理和日志记录。
- 支持在一次操作中打包多个文件。

本项目提供了一个强大的解决方案，通过加密可执行文件的节区并使用存根在运行时解密和加载原始代码，从而增强可执行文件的安全性。

### Content

## File: AES.cpp

```
#include "string.h"
#include "AES.h"

AES::AES(unsigned char* key)
{
	unsigned char sBox[] =
	{ /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */ 
		0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/  
		0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
		0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/ 
		0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/ 
		0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/ 
		0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
		0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/  
		0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/ 
		0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/ 
		0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/ 
		0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
		0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
		0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/ 
		0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
		0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/ 
		0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
	};
	unsigned char invsBox[256] = 
	{ /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f  */  
		0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb, /*0*/ 
		0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb, /*1*/
		0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e, /*2*/ 
		0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25, /*3*/ 
		0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92, /*4*/ 
		0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84, /*5*/ 
		0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06, /*6*/ 
		0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b, /*7*/
		0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73, /*8*/ 
		0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e, /*9*/
		0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b, /*a*/
		0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4, /*b*/ 
		0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f, /*c*/ 
		0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef, /*d*/ 
		0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61, /*e*/ 
		0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d  /*f*/
	}; 
	memcpy(Sbox, sBox, 256);
	memcpy(InvSbox, invsBox, 256);
	KeyExpansion(key, w);
}

AES::~AES()
{

}

unsigned char* AES::Cipher(unsigned char* input)
{
	unsigned char state[4][4];
	int i,r,c;

	for(r=0; r<4; r++)
	{
		for(c=0; c<4 ;c++)
		{
			state[r][c] = input[c*4+r];
		}
	}

	AddRoundKey(state,w[0]);

	for(i=1; i<=10; i++)
	{
		SubBytes(state);
		ShiftRows(state);
		if(i!=10)MixColumns(state);
		AddRoundKey(state,w[i]);
	}

	for(r=0; r<4; r++)
	{
		for(c=0; c<4 ;c++)
		{
			input[c*4+r] = state[r][c];
		}
	}

	return input;
}

unsigned char* AES::InvCipher(unsigned char* input)
{
	unsigned char state[4][4];
	int i,r,c;

	for(r=0; r<4; r++)
	{
		for(c=0; c<4 ;c++)
		{
			state[r][c] = input[c*4+r];
		}
	}

	AddRoundKey(state, w[10]);
	for(i=9; i>=0; i--)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, w[i]);
		if(i)
		{
			InvMixColumns(state);
		}
	}
	
	for(r=0; r<4; r++)
	{
		for(c=0; c<4 ;c++)
		{
			input[c*4+r] = state[r][c];
		}
	}

	return input;
}

void* AES::Cipher(void* input, int length)
{
	unsigned char* in = (unsigned char*) input;
	int i;
	if(!length)
	{
		while(*(in+length++));
		in = (unsigned char*) input;
	}
	for(i=0; i<length; i+=16)
	{
		Cipher(in+i);
	}
	return input;
}

void* AES::InvCipher(void* input, int length)
{
	unsigned char* in = (unsigned char*) input;
	int i;
	for(i=0; i<length; i+=16)
	{
		InvCipher(in+i);
	}
	return input;
}

void AES::KeyExpansion(unsigned char* key, unsigned char w[][4][4])
{
	int i,j,r,c;
	unsigned char rc[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
	for(r=0; r<4; r++)
	{
		for(c=0; c<4; c++)
		{
			w[0][r][c] = key[r+c*4];
		}
	}
	for(i=1; i<=10; i++)
	{
		for(j=0; j<4; j++)
		{
			unsigned char t[4];
			for(r=0; r<4; r++)
			{
				t[r] = j ? w[i][r][j-1] : w[i-1][r][3];
			}
			if(j == 0)
			{
				unsigned char temp = t[0];
				for(r=0; r<3; r++)
				{
					t[r] = Sbox[t[(r+1)%4]];
				}
				t[3] = Sbox[temp];
				t[0] ^= rc[i-1];
			}
			for(r=0; r<4; r++)
			{
				w[i][r][j] = w[i-1][r][j] ^ t[r];
			}
		}
	}
}

unsigned char AES::FFmul(unsigned char a, unsigned char b)
{
	unsigned char bw[4];
	unsigned char res=0;
	int i;
	bw[0] = b;
	for(i=1; i<4; i++)
	{
		bw[i] = bw[i-1]<<1;
		if(bw[i-1]&0x80)
		{
			bw[i]^=0x1b;
		}
	}
	for(i=0; i<4; i++)
	{
		if((a>>i)&0x01)
		{
			res ^= bw[i];
		}
	}
	return res;
}

void AES::SubBytes(unsigned char state[][4])
{
	int r,c;
	for(r=0; r<4; r++)
	{
		for(c=0; c<4; c++)
		{
			state[r][c] = Sbox[state[r][c]];
		}
	}
}

void AES::ShiftRows(unsigned char state[][4])
{
	unsigned char t[4];
	int r,c;
	for(r=1; r<4; r++)
	{
		for(c=0; c<4; c++)
		{
			t[c] = state[r][(c+r)%4];
		}
		for(c=0; c<4; c++)
		{
			state[r][c] = t[c];
		}
	}
}

void AES::MixColumns(unsigned char state[][4])
{
	unsigned char t[4];
	int r,c;
	for(c=0; c< 4; c++)
	{
		for(r=0; r<4; r++)
		{
			t[r] = state[r][c];
		}
		for(r=0; r<4; r++)
		{
			state[r][c] = FFmul(0x02, t[r])
						^ FFmul(0x03, t[(r+1)%4])
						^ FFmul(0x01, t[(r+2)%4])
						^ FFmul(0x01, t[(r+3)%4]);
		}
	}
}

void AES::AddRoundKey(unsigned char state[][4], unsigned char k[][4])
{
	int r,c;
	for(c=0; c<4; c++)
	{
		for(r=0; r<4; r++)
		{
			state[r][c] ^= k[r][c];
		}
	}
}

void AES::InvSubBytes(unsigned char state[][4])
{
	int r,c;
	for(r=0; r<4; r++)
	{
		for(c=0; c<4; c++)
		{
			state[r][c] = InvSbox[state[r][c]];
		}
	}
}

void AES::InvShiftRows(unsigned char state[][4])
{
	unsigned char t[4];
	int r,c;
	for(r=1; r<4; r++)
	{
		for(c=0; c<4; c++)
		{
			t[c] = state[r][(c-r+4)%4];
		}
		for(c=0; c<4; c++)
		{
			state[r][c] = t[c];
		}
	}
}

void AES::InvMixColumns(unsigned char state[][4])
{
	unsigned char t[4];
	int r,c;
	for(c=0; c< 4; c++)
	{
		for(r=0; r<4; r++)
		{
			t[r] = state[r][c];
		}
		for(r=0; r<4; r++)
		{
			state[r][c] = FFmul(0x0e, t[r])
						^ FFmul(0x0b, t[(r+1)%4])
						^ FFmul(0x0d, t[(r+2)%4])
						^ FFmul(0x09, t[(r+3)%4]);
		}
	}
}

```

----------------------------------------

## File: CD-PACKER.cpp

```
﻿#include "stdafx.h"
#include "string"
#include <windows.h>
#include <stdio.h>
#include "..//CD-PACKER/CPeFileOper.h"

using namespace std;




//读入shelled codelodercode pelodecode文件
//加壳

int main() {

	CPeFileOper cd_Pe;



	char path[MAX_PATH] = "E:\\1.exe";
	// 1. 打开被加壳程序
	int nTargetSize = 0;
	char* pTargetBuff = cd_Pe.GetFileData(path, &nTargetSize);

	//加载stub.dll
	StubInfo stub = { 0 };
	cd_Pe.LoadStub(&stub);

	//初始化检查 1.shelled需要有重定位表
	cd_Pe.checkRelocation((DWORD)stub.dllbase);
	//初始化检查 2.检查是否有tls表 //如果程序有tls表 会关掉随机基址 所以这里需要我们检查一下

	//初始化检查 3.检测傀儡注入的空间是否够 这个不用管 我们的add section函数里面已经写好了
	//初始化检查 4.检查是否为32位程序
	//压缩shelled
	//计算、填充param_pe_loader的结构体
	//1.首部jmp的size

}
```

----------------------------------------

## File: CPeFileOper.cpp

```
#include "CPeFileOper.h"
#include "AES.h"

CPeFileOper::~CPeFileOper()
{
}





//************************************************************
// : OpenPeFile
// ˵: PEļ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_ const char* path ļ· 
//   ֵ: HANDLE ļ
HANDLE CPeFileOper::OpenPeFile(_In_ const char* path) {
	return CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

//************************************************************
// : GetFileData
// ˵: ȡļݺʹС
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_ const char* pFilePath ļ· _Out_opt_ int* nFileSize ļС
//   ֵ: char* ļ
//************************************************************
char* CPeFileOper::GetFileData(_In_ const char* pFilePath,
	_Out_opt_ int* nFileSize) {
	// ļ
	HANDLE hFile = OpenPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// ȡļС
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// Կռ
	char* pFileBuff = new char[dwSize]{0};

	// ȡļݵѿռ
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// ѿռ䷵
	return pFileBuff;
}


//************************************************************
// : GetDosHeader
// ˵: ȡDosͷ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_  char* pFileData ļ׵ַ
//   ֵ: IMAGE_DOS_HEADER* Dosͷ
//************************************************************
IMAGE_DOS_HEADER* CPeFileOper::GetDosHeader(_In_ char* pFileData)
{
	return (IMAGE_DOS_HEADER*)pFileData;
}

//************************************************************
// : GetNtHeader
// ˵: ȡNtͷ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_  char* pFileData ļ׵ַ
//   ֵ: IMAGE_FILE_HEADER* Ntͷ
//************************************************************
IMAGE_NT_HEADERS* CPeFileOper::GetNtHeader(_In_ char* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew+(SIZE_T)pFileData);
}

//************************************************************
// : GetFileHead
// ˵: ȡļͷ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_  char* pFileData ļ׵ַ
//   ֵ: IMAGE_FILE_HEADER* ļͷ
//************************************************************
IMAGE_FILE_HEADER* CPeFileOper::GetFileHead(_In_ char* pFileData)
{
	return &GetNtHeader(pFileData)->FileHeader;
}



//************************************************************
// : GetOptionHeader
// ˵: ȡѡͷ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_  char* pFileData ļ׵ַ
//   ֵ: IMAGE_OPTIONAL_HEADER* ѡͷ
//************************************************************
IMAGE_OPTIONAL_HEADER* CPeFileOper::GetOptionHeader(_In_ char* pFileData)
{
	return &GetNtHeader(pFileData)->OptionalHeader;
}

//************************************************************
// : GetLastSection
// ˵: ȡһ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 : _In_  char* pFileData ļ׵ַ
//   ֵ: IMAGE_SECTION_HEADER* ͷ
//************************************************************
IMAGE_SECTION_HEADER* CPeFileOper::GetLastSection(_In_ char* pFileData)
{
	//ȡθ
	DWORD dwScnCount = GetFileHead(pFileData)->NumberOfSections;
	//ȡһ
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	//õһЧ
	return pScn + (dwScnCount - 1);
}


//************************************************************
// : AlignMent
// ˵: ĴС
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 1: _In_ int size С
// 	 2: _In_ int alignment 
//   ֵ: int ĴС
//************************************************************
int CPeFileOper::AlignMent(_In_ int size, _In_ int alignment)
{
	return (size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
}



//************************************************************
// : GetSection
// ˵: ȡֵָͷ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 1: _In_ char* pFileData Ŀļ׵ַ
// 	 2:  _In_ const char* scnName 
//   ֵ: IMAGE_SECTION_HEADER* ͷ
//************************************************************
IMAGE_SECTION_HEADER* CPeFileOper::GetSection(_In_ char* pFileData, _In_ const char* scnName)
{
	//ȡθʽ
	DWORD dwScnCount = GetFileHead(pFileData)->NumberOfSections;
	//ȡһ
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	char buf[10] = { 0 };
	//
	for (DWORD i=0;i< dwScnCount;i++)
	{
		memcpy_s(buf,8,(char*)pScn[i].Name,8);
		//жǷͬ
		if (strcmp(buf,scnName)==0)
		{
			return pScn + i;
		}
	}
	return nullptr;
}



//************************************************************
// : AddSection
// ˵: һµ
// 	 : CDxiaodong
// ʱ	 : 2018/12/1
// 	 1: char*& pFileBuff ļ׵ַ
// 	 2: int& fileSize ļС
// 	 3: const char* scnName Ҫӵ
// 	 4: int scnSize		 ҪӵδС
//   ֵ: void
//************************************************************
void CPeFileOper::AddSection(char*& pFileBuff, int& fileSize, const char* scnName, int scnSize)
{
	//ļͷθ
	GetFileHead(pFileBuff)->NumberOfSections++;
	//εͷ
	IMAGE_SECTION_HEADER* pNewScn = NULL;
	pNewScn = GetLastSection(pFileBuff);
	//ε
	memcpy(pNewScn->Name,scnName,8);
	//εĴС(ʵʴС/ĴС)
	pNewScn->Misc.VirtualSize = scnSize;
	pNewScn->SizeOfRawData = AlignMent(scnSize,GetOptionHeader(pFileBuff)->FileAlignment);
	//ελ(RVA/FOA)
	pNewScn->PointerToRawData = AlignMent(fileSize, GetOptionHeader(pFileBuff)->FileAlignment);
	//εڴƫ=һεڴƫ+һεĴС(ڴĴС)------------------

	pNewScn->VirtualAddress = (pNewScn - 1)->VirtualAddress + AlignMent((pNewScn-1)->SizeOfRawData,GetOptionHeader(pFileBuff)->SectionAlignment);
	
	//ε
	pNewScn->Characteristics = 0xE00000E0;

	//޸չͷӳС
	GetOptionHeader(pFileBuff)->SizeOfImage =pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	//ļݵĶѿռС
	int newSize = pNewScn->PointerToRawData + pNewScn->SizeOfRawData;
	char* pNewBuff = new char[newSize]{0};
	memcpy(pNewBuff,pFileBuff,fileSize);
	//ͷžɵĻ
	delete pFileBuff;

	//µĻ׵ַļĴСβ(޸ʵ)
	fileSize = newSize;
	pFileBuff = pNewBuff;
}


//************************************************************
// : SavePEFile
// ˵: ļ浽ָ·
// 	 : CDxiaodong
// ʱ	 : 2018/12/2
// 	 1: char*& pFileBuff ļ׵ַ
// 	 2: int& size ļС
// 	 3: _In_ const char*path ļ
//   ֵ: BOOL ļǷɹ
//************************************************************
BOOL CPeFileOper::SavePEFile(_In_ const char* pFileData, _In_ int size, _In_ const char*path)
{
	HANDLE hFile = CreateFileA( 
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile==INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	DWORD dwWrite = 0;
	//д뵽ļ
	WriteFile(hFile,pFileData,size,&dwWrite,NULL);
	//رļ
	CloseHandle(hFile);
	return dwWrite == size;

}


//************************************************************
// : LoadStub
// ˵: stub.dll
// 	 : CDxiaodong
// ʱ	 : 2018/12/2
// 	 1: StubInfo* pStub stubϢĽṹ
//   ֵ: void
//************************************************************
void CPeFileOper::LoadStub(StubInfo* pStub)
{
	//ͨLoadLibararystub.dll
	pStub->dllbase = (char*)LoadLibraryEx(L"stub.dll",NULL,DONT_RESOLVE_DLL_REFERENCES);

	//ȡDll
	pStub->pfnStart = (DWORD)GetProcAddress((HMODULE)pStub->dllbase,"Start");
	//ȡStubConfṹַ
	pStub->pStubConf = (StubConf*)GetProcAddress((HMODULE)pStub->dllbase,"g_conf");
}


//************************************************************
// : Encrypt
// ˵: ĿĴ
// 	 : CDxiaodong
// ʱ	 : 2018/12/2
// 	 : _In_ const char* pFileData Ŀļ׵ַ
// 	 : _In_  StubInfo* pStub stubϢĽṹ
//   ֵ: void
//************************************************************
void CPeFileOper::Encrypt(_In_ char* pFileData, _In_  StubInfo pStub)
{

	// ӿǳϢ浽stubĵṹ.
	pStub.pStubConf->oep = GetOptionHeader(pFileData)->AddressOfEntryPoint;
	pStub.pStubConf->nImportVirtual = GetOptionHeader(pFileData)->DataDirectory[1].VirtualAddress;
	pStub.pStubConf->nImportSize = GetOptionHeader(pFileData)->DataDirectory[1].Size;
	pStub.pStubConf->nResourceVirtual = GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress;
	pStub.pStubConf->nResourceSize = GetOptionHeader(pFileData)->DataDirectory[2].Size;
	pStub.pStubConf->nRelocVirtual = GetOptionHeader(pFileData)->DataDirectory[5].VirtualAddress;
	pStub.pStubConf->nRelocSize = GetOptionHeader(pFileData)->DataDirectory[5].Size;
	pStub.pStubConf->nTlsVirtual = GetOptionHeader(pFileData)->DataDirectory[9].VirtualAddress;
	pStub.pStubConf->nTlsSize = GetOptionHeader(pFileData)->DataDirectory[9].Size;



	unsigned char key[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//ʼaes
	AES aes(key);

	//ȡ
	DWORD dwSectionCount = GetFileHead(pFileData)->NumberOfSections;
	//ȡһ
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	//ڱ
	pStub.pStubConf->data[20][2] = { 0 };
	pStub.pStubConf->index = 0;
	
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".tls");
		//Դκtlsβ
		if (dwIsRsrc==0|| dwIsTls==0)
		{
			continue;
		}
		else       //ʼ
		{
			//ȡε׵ַʹС
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)pFileData;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//޸Ϊд
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//Ŀ
			aes.Cipher(pTargetSection, dwTargetSize);
			//޸Ļԭ
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//ݵϢṹ
			pStub.pStubConf->data[pStub.pStubConf->index][0] = pFirstSection[i].VirtualAddress;
			pStub.pStubConf->data[pStub.pStubConf->index][1] = dwTargetSize;
			pStub.pStubConf->index++;
		}
	}
	memcpy(pStub.pStubConf->key, key, 16);
}



//************************************************************
// : ClearDataDir
// ˵: Ŀ¼
// 	 : CDxiaodong
// ʱ	 : 2018/12/2
// 	 : _In_ const char* pFileData Ŀļ׵ַ
// 	 : _In_  StubInfo* pStub stubϢĽṹ
//   ֵ: void
//************************************************************
void CPeFileOper::ClearDataDir(_In_ char* pFileData, _In_  StubInfo pStub)
{
	//ȡĿ¼ĸ
	DWORD dwNumOfDataDir = GetOptionHeader(pFileData)->NumberOfRvaAndSizes;
	//Ŀ¼ĸ
	pStub.pStubConf->dwNumOfDataDir = dwNumOfDataDir;
	//ʼĿ¼Ľṹ
	pStub.pStubConf->dwDataDir[20][2] = 0;
	//Ŀ¼
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i==2)
		{
			continue;
		}
		//Ŀ¼
		pStub.pStubConf->dwDataDir[i][0] = GetOptionHeader(pFileData)->DataDirectory[i].VirtualAddress;
		pStub.pStubConf->dwDataDir[i][1] = GetOptionHeader(pFileData)->DataDirectory[i].Size;
		//Ŀ¼
		GetOptionHeader(pFileData)->DataDirectory[i].VirtualAddress = 0;
		GetOptionHeader(pFileData)->DataDirectory[i].Size = 0;
	}

}
//************************************************************
// : checkRelocation
// ˵: ޸stub.dllضλ
// 	 : CDxiaodong
//************************************************************
void CPeFileOper::checkRelocation(DWORD stubDllbase)
{
	//ҵstub.dllضλ
	DWORD dwRelRva = GetOptionHeader((char*)stubDllbase)->DataDirectory[5].VirtualAddress;
	IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva + stubDllbase);
	
}

void CPeFileOper::checktlstable(DWORD stubDllbase) {
	DWORD tlstable = GetOptionHeader((char*)stubDllbase)->DataDirectory[9].VirtualAddress;

}

void CPeFileOper::check32or64(DWORD stubDllbase) {



}

//************************************************************
// : FixStubRelocation
// ˵: ޸stub.dllضλ
// 	 : CDxiaodong
// ʱ	 : 2018/12/3
// 	 : DWORD stubDllbase stub.dllĻַ
// 	 : DWORD stubTextRva stub.dllĴRVA
// 	 : DWORD targetDllbase ĿļĬϼػַ
// 	 : DWORD targetNewScnRva ĿļεRVA
//   ֵ: void
//************************************************************
 void CPeFileOper::FixStubRelocation(DWORD stubDllbase, DWORD stubTextRva, DWORD targetDllbase, DWORD targetNewScnRva)
 {
	//ҵstub.dllضλ
	 DWORD dwRelRva = GetOptionHeader((char*)stubDllbase)->DataDirectory[5].VirtualAddress;
	 IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva+stubDllbase);
	
	 //ضλ
	 while (pRel->SizeOfBlock)
	 {
		 struct TypeOffset
		 {
			 WORD offset : 12;
			 WORD type : 4;

		 };
		 TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		 DWORD dwCount = (pRel->SizeOfBlock-8)/2;	//Ҫضλ
		 for (DWORD i = 0; i < dwCount; i++)
		 {
			 if (pTypeOffset[i].type!=3)
			 {
				 continue;
			 }
			 //Ҫضλĵַ
			 DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + stubDllbase);

			 DWORD dwOld;
			 //޸Ϊд
			 VirtualProtect(pFixAddr,4,PAGE_READWRITE,&dwOld);
			 //ȥdllǰػַ
			 *pFixAddr -= stubDllbase;
			 //ȥĬϵĶRVA
			 *pFixAddr -= stubTextRva;
			 //Ŀļļػַ
			 *pFixAddr += targetDllbase;
			 //εĶRVA
			 *pFixAddr += targetNewScnRva;
			 //޸Ļȥ
			 VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		 }
		 //лһضλ
		 pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	 }

 }






 
```

----------------------------------------

## File: stub.cpp

```
﻿
```

----------------------------------------

