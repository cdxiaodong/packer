#pragma once


// InputInfo �Ի���

class InputInfo : public CDialogEx
{
	DECLARE_DYNAMIC(InputInfo)

public:
	InputInfo(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~InputInfo();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG2 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	void SetDate();
	virtual BOOL OnInitDialog();
	void SetDisable(DWORD dwId);
};
