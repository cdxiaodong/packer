#include "stdafx.h"
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