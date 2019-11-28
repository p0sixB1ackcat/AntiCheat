
// Ring3AppDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Ring3App.h"
#include "Ring3AppDlg.h"
#include "afxdialogex.h"
#include "FileIni.h"
#include "DeviceControl.h"
#include <tlhelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRing3AppDlg 对话框



CRing3AppDlg::CRing3AppDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_RING3APP_DIALOG, pParent)
    , m_ProcessIdString(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRing3AppDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Text(pDX, IDC_EDIT1, m_ProcessIdString);
}

BEGIN_MESSAGE_MAP(CRing3AppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CRing3AppDlg::OnBnClickedButton1)
    ON_BN_CLICKED(IDC_BUTTON2, &CRing3AppDlg::OnBnClickedButton2)
    ON_BN_CLICKED(IDC_BUTTON3, &CRing3AppDlg::OnBnClickedButton3)
    ON_BN_CLICKED(IDC_BUTTON4, &CRing3AppDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CRing3AppDlg 消息处理程序

BOOL CRing3AppDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRing3AppDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRing3AppDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CRing3AppDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//打开notepad进程句柄
void CRing3AppDlg::OnBnClickedButton1()
{
    HANDLE hProcess = NULL;
    ULONG dwProcessId = 0;
    CString cLocation;
    BYTE pBuffer[0x100] = { 0x00 };
    SIZE_T dwRet = 0;

    UpdateData(TRUE);
    if (m_ProcessIdString.GetLength() == 0)
    {
        MessageBox(TEXT("请输入进程Id"), TEXT("Message"), 0);
        return;
    }

    dwProcessId = _wtoi64(m_ProcessIdString.GetBuffer());
    
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,FALSE,dwProcessId);
    if (!hProcess)
    {
        cLocation.Format(TEXT("打开进程Id:%d失败!"), dwProcessId);
        MessageBox(cLocation, TEXT("Message"), 0);
        return;
    }

    if (!ReadProcessMemory(hProcess, 0, pBuffer, 0x100, &dwRet))
    {
        cLocation.Format(TEXT("读取进程数据失败:%d!"), GetLastError());
        MessageBox(cLocation, TEXT("Message"), 0);
        return;
    }

    CloseHandle(hProcess);
    
}

//更新规则
void CRing3AppDlg::OnBnClickedButton2()
{
    // TODO: 在此添加控件通知处理程序代码
    char* pWhiteList = NULL;
    int dwWideStrLen = 0;
    WCHAR* pwWhitelist = NULL;
   
    loadwhitelist(&pWhiteList);

    if (pWhiteList)
    {
        dwWideStrLen = MultiByteToWideChar(0, 0, pWhiteList, strlen(pWhiteList) + 1, NULL, 0);
        pwWhitelist = (wchar_t*)malloc(dwWideStrLen * sizeof(WCHAR));
        if (!pwWhitelist)
            goto FINISH;

        MultiByteToWideChar(0, 0, pWhiteList, strlen(pWhiteList) + 1, pwWhitelist, dwWideStrLen);
        SendDeviceIoControl(ACCTL_CODE_SET_WHITE_LIST, pwWhitelist, dwWideStrLen * sizeof(WCHAR));
    }
    
    FINISH:
    if (pWhiteList)
        free(pWhiteList);
    if (pwWhitelist)
        free(pwWhitelist);
}

//安装驱动
void CRing3AppDlg::OnBnClickedButton3()
{
    int dwErrorCode = 0;
    // TODO: 在此添加控件通知处理程序代码
    CString cLocation;

    do
    {
        if (!InstallMiniFilter())
        {
            dwErrorCode = GetLastError();
            cLocation.Format(TEXT("安装驱动失败:%d!"), dwErrorCode);
            MessageBox(cLocation,TEXT("Message"),0);
            break;
        }
        if (!StartFilter())
        {
            dwErrorCode = GetLastError();
            cLocation.Format(TEXT("开启驱动失败:%d!"), dwErrorCode);
            MessageBox(cLocation, TEXT("Message"), 0);
            break;
        }  
    } while (false);
   

    return;
}

//卸载驱动
void CRing3AppDlg::OnBnClickedButton4()
{
    int dwErrorCode = 0;
    // TODO: 在此添加控件通知处理程序代码

    do
    {
        if (!StopFilter())
        {
            dwErrorCode = GetLastError();
            break;
        }
        if (!UnInstallMiniFilter())
        {
            dwErrorCode = GetLastError();
            break;
        }
        
    } while (false);
    
}
