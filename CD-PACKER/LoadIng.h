#pragma once
#include "PictureEx.h"
#include "afxwin.h"

// LoadIng �Ի���

class LoadIng : public CDialogEx
{
	DECLARE_DYNAMIC(LoadIng)

public:
	LoadIng( CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~LoadIng();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CPictureEx m_loadPic;
	bool m_isSetPassword;
	bool m_isSetTimeOut;
};
