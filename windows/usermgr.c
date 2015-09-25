#include <windows.h>
#include "pluginapi.h"
#include "UserMgr.h"
// JPR 123007: Added Userenv.h for the new BuiltAccountEnv function (Also Added Userenv.lib in the Link->Object/Library modules in the project settings)
// NOTE Platform SDK is needed for this header (The February 2003 build is the latest version which work with VC6)
#include <Userenv.h>
#include <winnls.h>
#include <AccCtrl.h>
#include <AclApi.h>
#define _WIN32_WINNT 0x0501
#include <WinNT.h>
#include <Sddl.h>

HINSTANCE g_hInstance;

HWND g_hwndParent;

void ShowError (char *Errormessage);

BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
    g_hInstance = hInst;
	return TRUE;
}

static UINT_PTR PluginCallback(enum NSPIM msg)
{
  return 0;
}

NTSTATUS AddPrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege)
{
	NTSTATUS ntsResult;

	// Create an LSA_UNICODE_STRING for the privilege name(s).

	ntsResult = LsaAddAccountRights(PolicyHandle,  // An open policy handle.
									AccountSID,    // The target SID.
									&lucPrivilege, // The privilege(s).
									1);            // Number of privileges.
									                
	return ntsResult;

} 

NTSTATUS RemovePrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege)
{
	NTSTATUS ntsResult;

	// Create an LSA_UNICODE_STRING for the privilege name(s).

	ntsResult = LsaRemoveAccountRights( PolicyHandle,  // An open policy handle.
										AccountSID,    // The target SID.
										FALSE,         // Delete all rights? We should not even think about that...
										&lucPrivilege, // The privilege(s).
										1);            // Number of privileges.

	return ntsResult;

} 

NET_API_STATUS EnablePrivilege(LPCTSTR dwPrivilege)
{
   HANDLE hProcessToken = NULL;

   TOKEN_PRIVILEGES tkp; 
   
   NET_API_STATUS nStatus;

   if (!OpenProcessToken(GetCurrentProcess(), 
                         TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, 
                         &hProcessToken)) 
   {
	   nStatus=GetLastError();
	   return nStatus;
   }

   tkp.PrivilegeCount = 1; 
   tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

   if (!LookupPrivilegeValue(NULL, 
	                         dwPrivilege, 
		                     &tkp.Privileges[0].Luid))
   {
	   nStatus=GetLastError();
       CloseHandle(hProcessToken);
	   return nStatus;
   }
   if (!AdjustTokenPrivileges(hProcessToken, 
	                          FALSE, 
		                      &tkp, 
		                      0, 
		                      NULL, 
		                      0)) 
   {
	   nStatus=GetLastError();
       CloseHandle(hProcessToken);
	   return nStatus;
   }

   CloseHandle(hProcessToken);
   return 0;
}

LSA_HANDLE GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	// Object attributes are reserved, so initialize to zeroes.
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// Get a handle to the Policy object.
	ntsResult = LsaOpenPolicy(NULL,			   //only localhost
							&ObjectAttributes, //Object attributes.
							POLICY_ALL_ACCESS, //Desired access permissions.
							&lsahPolicyHandle);//Receives the policy handle.
							

	if (ntsResult != STATUS_SUCCESS)
	{
		// An error occurred. Display it as a win32 error code.
		return NULL;
	} 
	return lsahPolicyHandle;
}

BOOL InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
	return FALSE;

	if (NULL != pwszString) 
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
		return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length =  (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength= (USHORT)(dwLen+1) * sizeof(WCHAR);

	return TRUE;
}

BOOL GetAccountSid(LPTSTR SystemName, LPTSTR AccountName, PSID *Sid) 
{
	LPTSTR ReferencedDomain = NULL;
	DWORD cbSid = 128;    /* initial allocation attempt */
	DWORD cbReferencedDomain = 16; /* initial allocation size */
	SID_NAME_USE peUse;
	BOOL bSuccess = FALSE; /* assume this function will fail */

	__try {
		/*
		 * initial memory allocations
		 */
		if ((*Sid = HeapAlloc(GetProcessHeap(), 0, cbSid)) == NULL)
			__leave;

		if ((ReferencedDomain = (LPTSTR) HeapAlloc(GetProcessHeap(), 0,
				       cbReferencedDomain)) == NULL) __leave;

		/*
		 * Obtain the SID of the specified account on the specified system.
		 */
		while (!LookupAccountName(SystemName, AccountName, *Sid, &cbSid,
					  ReferencedDomain, &cbReferencedDomain,
					  &peUse))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				/* reallocate memory */
				if ((*Sid = HeapReAlloc(GetProcessHeap(), 0,
					*Sid, cbSid)) == NULL) __leave;

				if ((ReferencedDomain= (LPTSTR) HeapReAlloc(
					GetProcessHeap(), 0, ReferencedDomain,
					cbReferencedDomain)) == NULL)
				__leave;
			}
			else 
				__leave;
		}
		bSuccess = TRUE;
	} /* finally */
	__finally {

		/* Cleanup and indicate failure, if appropriate. */

		HeapFree(GetProcessHeap(), 0, ReferencedDomain);

		if (!bSuccess) {
			if (*Sid != NULL) {
				HeapFree(GetProcessHeap(), 0, *Sid);
				*Sid = NULL;
			}
		}

	}

	return (bSuccess);
}

NSISFunction(CreateAccount)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		USER_INFO_1 ui;	
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static char userid[256];
		static char passwd[256];
		static char comment[1024];

		static WCHAR u_userid[256];
		static WCHAR u_passwd[256];
		static WCHAR u_comment[1024];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(passwd);
		swprintf(u_passwd, L"%S", passwd);

		popstring(comment);
		swprintf(u_comment, L"%S", comment);

		ui.usri1_name = u_userid;
		ui.usri1_password = u_passwd;
		ui.usri1_password_age = 0;
		ui.usri1_priv = USER_PRIV_USER;
		ui.usri1_home_dir = NULL;
		ui.usri1_comment = u_comment;
		ui.usri1_flags = UF_DONT_EXPIRE_PASSWD | UF_SCRIPT;


		//
		// Call the NetUserAdd function, specifying level 1.
		//
		nStatus = NetUserAdd(NULL,
							dwLevel,
							(LPBYTE)&ui,
							&dwError);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


// JPR 123007: Added CreateAccountEx function
NSISFunction(CreateAccountEx)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		USER_INFO_2 ui;	
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static char userid[256];
		static char passwd[256];
		static char comment[1024];
		static char fullname[256];
		static char usr_comment[1024];
		static char flags[1024];

		static WCHAR u_userid[256];
		static WCHAR u_passwd[256];
		static WCHAR u_comment[1024];
		static WCHAR u_fullname[256];
		static WCHAR u_usr_comment[1024];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(passwd);
		swprintf(u_passwd, L"%S", passwd);

		popstring(comment);
		swprintf(u_comment, L"%S", comment);

		popstring(fullname);
		swprintf(u_fullname, L"%S", fullname);

		popstring(usr_comment);
		swprintf(u_usr_comment, L"%S", usr_comment);

		popstring(flags);

		ui.usri2_name=u_userid;  
		ui.usri2_password=u_passwd;  
		ui.usri2_priv=USER_PRIV_USER;
		ui.usri2_home_dir=NULL;  
		ui.usri2_comment=u_comment;  
		ui.usri2_flags=UF_SCRIPT | UF_NORMAL_ACCOUNT;  
		if(strstr(flags,"UF_ACCOUNTDISABLE"))
		{
			ui.usri2_flags|=UF_ACCOUNTDISABLE;
		}
		if(strstr(flags,"UF_PASSWD_NOTREQD"))
		{
			ui.usri2_flags|=UF_PASSWD_NOTREQD;
		}
		if(strstr(flags,"UF_PASSWD_CANT_CHANGE"))
		{
			ui.usri2_flags|=UF_PASSWD_CANT_CHANGE;
		}
		if(strstr(flags,"UF_DONT_EXPIRE_PASSWD"))
		{
			ui.usri2_flags|=UF_DONT_EXPIRE_PASSWD;
		}
		ui.usri2_script_path=NULL;  
		ui.usri2_auth_flags=0;  
		ui.usri2_full_name=u_fullname;  
		ui.usri2_usr_comment=u_usr_comment;  
		ui.usri2_parms=NULL;
		ui.usri2_workstations=NULL;  
		ui.usri2_acct_expires=TIMEQ_FOREVER;
		ui.usri2_max_storage=USER_MAXSTORAGE_UNLIMITED;  
		ui.usri2_logon_hours=NULL;  
		ui.usri2_country_code=0;  
		ui.usri2_code_page=0;

		//
		// Call the NetUserAdd function, specifying level 2.
		//
		nStatus = NetUserAdd(NULL,
							dwLevel,
							(LPBYTE)&ui,
							&dwError);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


// JPR 123007: Added BuiltAccountEnv function
NSISFunction(BuiltAccountEnv)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		HANDLE hLogonToken = NULL;

		PROFILEINFO PI;

		static char userid[256];
		static char passwd[256];

		g_hwndParent=hwndParent;

		popstring(userid);

		popstring(passwd);

		nStatus=EnablePrivilege(SE_RESTORE_NAME);
		if (nStatus) 
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		if(!LogonUser(userid,
					".",
					passwd,
					LOGON32_LOGON_INTERACTIVE,
					LOGON32_PROVIDER_DEFAULT,
					&hLogonToken))
		{
			nStatus=GetLastError();
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		PI.dwSize=sizeof(PROFILEINFO);
		PI.dwFlags=0;
		PI.lpUserName=userid;
		PI.lpProfilePath=NULL;
		PI.lpDefaultPath=NULL;
		PI.lpServerName=NULL;
		PI.lpPolicyPath=NULL;
		PI.hProfile=HKEY_CURRENT_USER;

		if(!LoadUserProfile(hLogonToken,&PI))
		{
			nStatus=GetLastError();
			CloseHandle(hLogonToken);
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		if(!UnloadUserProfile(hLogonToken,PI.hProfile))
		{
			nStatus=GetLastError();
			CloseHandle(hLogonToken);
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		CloseHandle(hLogonToken);

		pushstring("OK");
		return;
	}
}


// JPR 123007: Added RegLoadUserHive function
NSISFunction(RegLoadUserHive)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];

		HKEY hKey;
		DWORD valueSize;

		static char NTUser_dat[256];
		static char DocumentsAndSettings[256];
		static char DocumentsAndSettingsT[256];
		static char SYSTEMDRIVE[256];

		PSID user_sid;

		LPTSTR strSid;

		g_hwndParent=hwndParent;

		popstring(userid);

		nStatus=EnablePrivilege(SE_RESTORE_NAME);
		if (nStatus) 
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		GetEnvironmentVariable("SYSTEMDRIVE",SYSTEMDRIVE,512);
		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			sprintf(userid, "ERROR %d", GetLastError());
			pushstring(userid);
			return;
		}

		if (!ConvertSidToStringSid(user_sid,&strSid))
		{
			sprintf(userid, "ERROR %d", GetLastError());
			pushstring(userid);
			return;
		}
		else
		{
			sprintf(DocumentsAndSettings,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s",strSid);
		}
		RegOpenKeyEx(HKEY_LOCAL_MACHINE,DocumentsAndSettings,0,KEY_READ,&hKey);
// JPR 011508 Get localized "Documents and Settings" string
		RegQueryValueEx(hKey,"ProfileImagePath",NULL,NULL,(LPVOID)DocumentsAndSettingsT,&valueSize);
// JPR 011508 Remove "%SystemDrive%\"
		sprintf(DocumentsAndSettings, "%s", &DocumentsAndSettingsT[14]);
		sprintf(NTUser_dat, "%s\\%s\\NTUSER.DAT", SYSTEMDRIVE,DocumentsAndSettings);
		RegCloseKey(hKey);
		nStatus = RegLoadKey(HKEY_USERS, userid, NTUser_dat);

		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR  %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


// JPR 123007: Added RegUnLoadUserHive function
NSISFunction(RegUnLoadUserHive)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];

		static char NTUSER_DAT[256];
		static char SYSTEMDRIVE[256];

		g_hwndParent=hwndParent;

		popstring(userid);

		nStatus = RegUnLoadKey(HKEY_USERS, userid);

		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}

NSISFunction(DeleteAccount)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];
		static WCHAR u_userid[256];

		memset( u_userid, 0, sizeof( u_userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		nStatus = NetUserDel(NULL, u_userid);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


// JPR 011208: Added GetCurrentUserName function
NSISFunction(GetCurrentUserName)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];
		DWORD Size=256;

		g_hwndParent=hwndParent;

		nStatus = GetUserName(userid, &Size);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus)
		{
			pushstring(userid);
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", GetLastError());
			pushstring(userid);
			return;
		}
	}
}


// JPR 012109: Added GetCurrentDomain function
NSISFunction(GetCurrentDomain)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;
		LPWKSTA_USER_INFO_1 wksta_info;

		static char userdomain[256];

		g_hwndParent=hwndParent;

		nStatus = NetWkstaUserGetInfo(NULL, 1, (LPBYTE *)&wksta_info);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			sprintf(userdomain, "%S", wksta_info->wkui1_logon_domain);	   
			pushstring(userdomain);
			if (wksta_info != NULL)NetApiBufferFree(wksta_info);
			return;
		}
		else
		{
			sprintf(userdomain, "ERROR %d", GetLastError());
			pushstring(userdomain);
			return;
		}
	}
}

// JPR 011208: Added GetLocalizedStdAccountName function
NSISFunction(GetLocalizedStdAccountName)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		static char pid[256];

		PSID pSid = NULL;

		char username[256];
		char domain[256];

		DWORD usize=256;
		DWORD dsize=256;

		DWORD SidSize = SECURITY_MAX_SID_SIZE;

		SID_NAME_USE snu;

		g_hwndParent=hwndParent;

		popstring(pid);

		pSid=LocalAlloc(LMEM_FIXED, SidSize);
		if(!ConvertStringSidToSid(pid,&pSid))
		{
			if (pSid != NULL)LocalFree(pSid);
			sprintf(pid,"ERROR");
			pushstring(pid);
			return;
		}
		if(!LookupAccountSid(NULL,pSid,username, &usize, domain, &dsize, &snu))
		{
			if (pSid != NULL)LocalFree(pSid);
			sprintf(pid,"ERROR");
			pushstring(pid);
			return;
		}
		if (pSid != NULL)LocalFree(pSid);
		sprintf(pid,"%s\\%s",domain,username);
		pushstring(pid);
		return;
	}
}

// JPR 020909: Added GetUserNameFromSID function
NSISFunction(GetUserNameFromSID)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		static char pid[256];

		PSID pSid = NULL;

		char username[256];
		char domain[256];

		DWORD usize=256;
		DWORD dsize=256;

		DWORD SidSize = SECURITY_MAX_SID_SIZE;

		SID_NAME_USE snu;

		g_hwndParent=hwndParent;

		popstring(pid);

		pSid=LocalAlloc(LMEM_FIXED, SidSize);
		if(!ConvertStringSidToSid(pid,&pSid))
		{
			if (pSid != NULL)LocalFree(pSid);
			sprintf(pid,"ERROR");
			pushstring(pid);
			return;
		}
		if(!LookupAccountSid(NULL,pSid,username, &usize, domain, &dsize, &snu))
		{
			if (pSid != NULL)LocalFree(pSid);
			sprintf(pid,"ERROR");
			pushstring(pid);
			return;
		}
		if (pSid != NULL)LocalFree(pSid);
		sprintf(pid,"%s",domain);
		if ( strcmp(domain,"") != 0 )sprintf(pid,"%s\\%s",domain,username);
		else sprintf(pid,"%s",username);
		pushstring(pid);
		return;
	}
}

// JPR 020909: Added GetSIDFromUserName function
NSISFunction(GetSIDFromUserName)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		PSID user_sid;

		static char userid[256];
		static char domain[256];
		LPTSTR strSid;

		g_hwndParent=hwndParent;

		popstring(domain);

		popstring(userid);

		if (!GetAccountSid(domain,userid,&user_sid))
		{
			pushstring("ERROR GetAccountSid");
			return;
		}

		if (!ConvertSidToStringSid(user_sid,&strSid))
		{
			pushstring("ERROR ConvertSidToStringSid");
			return;
		}
		else
		{
			sprintf(userid,"%s",strSid);
			pushstring(userid);
			return;
		}
	}
}

NSISFunction(GetUserInfo)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		LPUSER_INFO_2 ui;
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static char userid[256];
		static char field[256];
		static char response[1024];

		static WCHAR u_userid[256];
		static WCHAR u_field[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_field, 0, sizeof( u_field ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(field);
		_strupr(field);

		swprintf(u_field, L"%S", field);

		//
		//  Set up the USER_INFO_1 structure.
		//  USER_PRIV_USER: name identifies a user, 
		//  rather than an administrator or a guest.
		//  UF_SCRIPT: required for LAN Manager 2.0 and
		//  Windows NT and later.
		//

		nStatus = NetUserGetInfo(NULL, 
								u_userid, 
								dwLevel, 
								(LPBYTE *)&ui );

		if (nStatus != NERR_Success)
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
// JPR 011208: Freeing ui buffer properly
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"EXISTS") == 0 ) 
		{
			pushstring("OK");
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"FULLNAME") == 0 ) 
		{
			sprintf(response, "%S", ui->usri2_full_name);	   
			pushstring(response);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}


		if ( strcmp(field,"COMMENT") == 0 ) 
		{
			sprintf(response, "%S", ui->usri2_comment);	   
			pushstring(response);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"NAME") == 0 ) 
		{
			sprintf(response, "%S", ui->usri2_name);	   
			pushstring(response);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"HOMEDIR") == 0 ) 
		{
			sprintf(response, "%S", ui->usri2_home_dir);	   
			pushstring(response);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"PASSWD_STATUS") == 0 ) 
		{
			if ( ui->usri2_flags & UF_DONT_EXPIRE_PASSWD ) pushstring("NEVEREXPIRES");
			else
			{
				if ( ui->usri2_flags & UF_PASSWD_CANT_CHANGE )
				pushstring ("CANTCHANGE");
			}
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}
		if (ui != NULL)NetApiBufferFree(ui);
		pushstring("ERROR");
		return;
	}
}

NSISFunction(SetUserInfo)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		LPUSER_INFO_2 ui;
		LPUSER_INFO_2 uiTemp;
// JPR 123007: Needed to change a user password
		USER_INFO_1003 ui1003;
// JPR 020108: Use USER_INFO_1011 to change the users fullname instead of USER_INFO_1
		USER_INFO_1011 ui1011;
		DWORD dwLevel = 2;
		DWORD dwError = 0;
		NET_API_STATUS nStatus;

		static char userid[256];
		static char field[256];
		static char newvalue[256];
		static char response[1024];

		static WCHAR u_userid[256];
		static WCHAR u_field[256];
		static WCHAR u_pwd[256];
		static WCHAR u_fullname[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_field, 0, sizeof( u_field ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(field);
		_strupr(field);

		popstring(newvalue);

		swprintf(u_field, L"%S", field);


		nStatus = NetUserGetInfo(NULL, 
								u_userid, 
								dwLevel, 
								(LPBYTE *)&ui );

		if (nStatus != NERR_Success)
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
// JPR 011208: Freeing ui buffer properly
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

// JPR 011208: Copy ui buffer to a temp buffer so original buffer will not be invalidated
		if ((uiTemp = ui) == NULL)
		{
			sprintf(userid, "ERROR INVALID USERINFO");
			pushstring(userid);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		if ( strcmp(field,"FULLNAME") == 0 ) 
		{
			swprintf(u_fullname, L"%S", newvalue);
			ui1011.usri1011_full_name=u_fullname;
			dwLevel=1011;
		}

// JPR 123007: Added PASSWORD field
		if ( strcmp(field,"PASSWORD") == 0 ) 
		{
			swprintf(u_pwd, L"%S", newvalue);
			ui1003.usri1003_password=u_pwd;
			dwLevel=1003;
		}

		if ( strcmp(field,"COMMENT") == 0 ) 
		{
			swprintf(uiTemp->usri2_comment, L"%S", newvalue);	   
		}

		if ( strcmp(field,"NAME") == 0 ) 
		{
			swprintf(uiTemp->usri2_name, L"%S", newvalue);	   
		}

		if ( strcmp(field,"HOMEDIR") == 0 ) 
		{
			swprintf(uiTemp->usri2_home_dir, L"%S", newvalue);	   
		}

		if ( strcmp(field,"PASSWD_NEVER_EXPIRES") == 0 ) 
		{
			if (strcmp(newvalue, "YES") == 0)
				uiTemp->usri2_flags |= UF_DONT_EXPIRE_PASSWD;
			else
				uiTemp->usri2_flags |=~ UF_DONT_EXPIRE_PASSWD;
		}

// JPR 123007: Different for changing a user password
		if(dwLevel==1003)
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) &ui1003,
									NULL );
		}
// JPR 020108: Different for changing a user fullname
		else if(dwLevel==1011)
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) &ui1011,
									NULL );
		}
		else
		{
			nStatus = NetUserSetInfo(NULL, 
									u_userid, 
									dwLevel, 
									(LPBYTE) uiTemp,
									NULL );
		}

		if (nStatus != NERR_Success)
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			if (ui != NULL)NetApiBufferFree(ui);
			return;
		}

		pushstring("OK");
		if (ui != NULL)NetApiBufferFree(ui);
		return;
	}
}


// JPR 123007: Added ChangeUserPassword function
NSISFunction(ChangeUserPassword)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];
		static char oldpwd[256];
		static char newpwd[256];

		static WCHAR u_userid[256];
		static WCHAR u_oldpwd[256];
		static WCHAR u_newpwd[256];

		memset( userid, 0, sizeof( userid ) );

		g_hwndParent=hwndParent;

		popstring(userid);  
		swprintf(u_userid, L"%S", userid);

		popstring(oldpwd);  
		swprintf(u_oldpwd, L"%S", oldpwd);

		popstring(newpwd);  
		swprintf(u_newpwd, L"%S", newpwd);

		nStatus = NetUserChangePassword (NULL, u_userid, u_oldpwd, u_newpwd );

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus != NERR_Success)
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}

		pushstring("OK");
		return;
	}
}

NSISFunction(DeleteGroup)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char groupid[256];
		static WCHAR u_groupid[256];
		DWORD dwError = 0;

		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(groupid);  
		swprintf(u_groupid, L"%S", groupid);

		nStatus = NetLocalGroupDel(NULL, u_groupid );

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus == NERR_Success)
		{
			#ifdef _USRDLL
				pushstring("OK");
			#endif
			return;
		}
		else
		{
			#ifdef _USRDLL
				sprintf(groupid, "ERROR %d %d", nStatus, dwError);
				pushstring(groupid);
			#endif
			return;
		}
	}
}

NSISFunction(CreateGroup)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char groupid[256];
		static WCHAR u_groupid[256];
		static char comment[1024];
		static WCHAR u_comment[1024];
		DWORD dwError = 0;
		LOCALGROUP_INFO_1 ginfo;

		memset( u_groupid, 0, sizeof( u_groupid ) );
		memset( u_comment, 0, sizeof( u_comment) );

		g_hwndParent=hwndParent;

		popstring(groupid);  
		popstring(comment);

		memset (&ginfo,0,sizeof(ginfo));

		swprintf(u_groupid, L"%S", groupid);
		swprintf(u_comment, L"%S", comment);

		ginfo.lgrpi1_name = u_groupid;
		ginfo.lgrpi1_comment= u_comment;

		nStatus = NetLocalGroupAdd(NULL, 1, (LPBYTE)&ginfo, &dwError);

		//
		// If the call succeeds, inform the user.
		//

		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(groupid, "ERROR %d %d", nStatus, dwError);
			pushstring(groupid);
			return;
		}
	}
}

NSISFunction(AddToGroup)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		LOCALGROUP_MEMBERS_INFO_3 LMI;

		static char userid[256];
		static WCHAR u_userid[256];
		static char groupid[256];
		static WCHAR u_groupid[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(groupid);
		swprintf(u_groupid, L"%S", groupid);

// JPR 123007: Changed to NetLocalGroupAddMembers to make this function work
		LMI.lgrmi3_domainandname = u_userid;
		nStatus = NetLocalGroupAddMembers(NULL, u_groupid,3,(LPBYTE)&LMI,1);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


// JPR 011208: Added function IsMemberOfGroup
NSISFunction(IsMemberOfGroup)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
	   NET_API_STATUS nStatus;

	   LPLOCALGROUP_MEMBERS_INFO_1 pBuf = NULL;

	   DWORD dwLevel = 1;
	   DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	   DWORD dwEntriesRead = 0;
	   DWORD dwTotalEntries = 0;
	   DWORD dwResumeHandle = 0;

	   static char userid[256];
	   static char userid2[256];
	   static char groupid[256];
	   static WCHAR u_groupid[256];
	   static char groupid2[256];

	   memset( u_groupid, 0, sizeof( u_groupid ) );

	   g_hwndParent=hwndParent;

	   popstring(userid);

	   popstring(groupid);

	   //
	   // Call the NetLocalGroupGetMembers function 
	   //  specifying information level 1.
	   //
	   swprintf(u_groupid, L"%S", groupid);
	   nStatus = NetLocalGroupGetMembers(NULL,
										 u_groupid,
										 dwLevel,
										 (LPBYTE *) &pBuf,
										 dwPrefMaxLen,
										 &dwEntriesRead,
										 &dwTotalEntries,&dwResumeHandle);
		//
		// If the call succeeds,
		//
		if (nStatus == NERR_Success)
		{
			LPLOCALGROUP_MEMBERS_INFO_1 pTmpBuf;
			DWORD i;
			DWORD dwTotalCount = 0;

			if ((pTmpBuf = pBuf) != NULL)
			{
				//
				// Loop through the entries and 
				//  print the names of the local groups 
				//  to which the user belongs. 
				//
				for (i = 0; i < dwEntriesRead; i++)
				{

					if (pTmpBuf == NULL)
					{
						if (pBuf != NULL)NetApiBufferFree(pBuf);
						sprintf(userid, "ERROR: An access violation has occurred");
						pushstring(userid);
						return;
					}

					sprintf(userid2, "%S", pTmpBuf->lgrmi1_name);
					if(strcmp(userid2,userid) == 0)
					{
						if (pBuf != NULL)NetApiBufferFree(pBuf);
						pushstring("TRUE");
						return;
					}
					pTmpBuf++;
					dwTotalCount++;
				}
			}
			if (pBuf != NULL)NetApiBufferFree(pBuf);
			pushstring("FALSE");
			return;
		}
		else
		{
			if (pBuf != NULL)NetApiBufferFree(pBuf);
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}


NSISFunction(RemoveFromGroup)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		NET_API_STATUS nStatus;

		static char userid[256];
		static WCHAR u_userid[256];
		static char groupid[256];
		static WCHAR u_groupid[256];

		memset( u_userid, 0, sizeof( u_userid ) );
		memset( u_groupid, 0, sizeof( u_groupid ) );

		g_hwndParent=hwndParent;

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(groupid);
		swprintf(u_groupid, L"%S", groupid);

		nStatus = NetGroupDelUser(NULL, u_groupid, u_userid);

		//
		// If the call succeeds, inform the user.
		//
		if (nStatus == NERR_Success)
		{
			pushstring("OK");
			return;
		}
		else
		{
			sprintf(userid, "ERROR %d", nStatus);
			pushstring(userid);
			return;
		}
	}
}

NSISFunction(AddPrivilege)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING lucPrivilege;   

		static char tempbuf[1024];
		static char userid[256];
		static char privilege[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(privilege);
		swprintf(u_privilege, L"%S", privilege);

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring("ERROR GetAccountSid");
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring("ERROR GetPolicyHandle");
			return;
		}

		if (!InitLsaString(&lucPrivilege, u_privilege))
		{
			LsaClose(my_policy_handle);
			pushstring("ERROR InitLsaString");
			return;
		}

		if (AddPrivileges(user_sid, my_policy_handle, lucPrivilege) != STATUS_SUCCESS)
		{
			LsaClose(my_policy_handle);
			pushstring("ERROR AddPrivileges");
			return;
		}

		LsaClose(my_policy_handle);
		pushstring("OK");
		return;
	}
}

NSISFunction(SetRegKeyAccess)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		unsigned int i = 0;

		INT grant_or_revoke = GRANT_ACCESS;
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		DWORD dwRes;	  
		PSID user_sid;
		PACL pDacl=NULL;
		PACL pNewDacl=NULL;
		EXPLICIT_ACCESS ea;   
		PSECURITY_DESCRIPTOR pSD=NULL;

		static char tempbuf[1024];
		static char userid[256];
		static char hive[128];
		static char regkey[512];
		static char rights[8];
		char myhive[32];
		char myregkey[512];

		static WCHAR u_userid[256];
		unsigned long accessrights = 0;
		unsigned long aclentries = 64;

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(hive);
		popstring(regkey);
		popstring(rights);

		strcpy (myhive,"");

		if ( strcmp(hive,"HKLM") == 0 )
			strcpy(myhive,"MACHINE");

		if ( strcmp(hive,"HKCU") == 0 )
			strcpy(myhive,"CURRENT_USER");

		if ( strcmp(hive,"HKU") == 0 )
			strcpy(myhive,"USERS");

		if ( strcmp(hive,"HKCR") == 0 )
			strcpy(myhive,"CLASSES_ROOT");

		if ( strcmp (myhive,"") == 0 )
		{
			pushstring("ERROR Illegal Root Key (use HKLM|HKCU|HKU|HKCR)");
			return;
		}

		_snprintf(myregkey,sizeof(myregkey)-1,"%s\\%s",myhive,regkey);
		if ( strlen(rights) <= 0 ) 
		{
			grant_or_revoke = REVOKE_ACCESS;
		}

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring("ERROR GetAccountSid");
			return;
		}

		if(dwRes=GetNamedSecurityInfo(myregkey,SE_REGISTRY_KEY,DACL_SECURITY_INFORMATION,
									NULL,NULL,&pDacl,NULL,&pSD)!=ERROR_SUCCESS)
		{
			sprintf(tempbuf,"ERROR GetSecurityInfo %d", dwRes);
			pushstring( tempbuf);
			return;
		}

		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

		for (i=0;i<=strlen(rights);i++) 
		{
			switch(rights[i])
			{
				case '+':
					grant_or_revoke = GRANT_ACCESS;
					break;
				case '-':
					grant_or_revoke = DENY_ACCESS;
					break;
				case '=':
					grant_or_revoke = SET_ACCESS;
					break;
				case 'r':
					accessrights |= KEY_READ;
					break;
				case 'w':
					accessrights |= KEY_WRITE;
					break;
				case 'a':
					accessrights |= KEY_ALL_ACCESS;
					break;
				case 'x':
					accessrights |= KEY_EXECUTE;
					break;
				default:
				break;
			}
		}

		ea.grfAccessPermissions = accessrights;
		ea.grfAccessMode = grant_or_revoke;
		ea.grfInheritance= SUB_CONTAINERS_ONLY_INHERIT;
		ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
		ea.Trustee.ptstrName = user_sid;

		if(dwRes=SetEntriesInAcl(1,&ea,pDacl,&pNewDacl)!=ERROR_SUCCESS)
		{
			sprintf(tempbuf,"ERROR SetEntriesInAcl Error %d", dwRes);
			pushstring( tempbuf);
			return;
		}

		if (dwRes = SetNamedSecurityInfo(myregkey, SE_REGISTRY_KEY,DACL_SECURITY_INFORMATION,NULL,NULL,pNewDacl,NULL) != ERROR_SUCCESS)
		{
			sprintf(tempbuf,"ERROR SetNamedSecurityInfo %d", dwRes);
			pushstring( tempbuf);
			return;
		}

		sprintf(tempbuf,"OK");
		pushstring(tempbuf);
		return;
	}
}

NSISFunction(RemovePrivilege)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING lucPrivilege;   

		static char tempbuf[1024];
		static char userid[256];
		static char privilege[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(privilege);
		swprintf(u_privilege, L"%S", privilege);

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring("ERROR GetAccountSid");
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring("ERROR GetPolicyHandle");
			return;
		}

		if (!InitLsaString(&lucPrivilege, u_privilege))
		{
			LsaClose(my_policy_handle);
			pushstring("ERROR InitLsaString");
			return;
		}


		if (RemovePrivileges(user_sid, my_policy_handle, lucPrivilege) != STATUS_SUCCESS)
		{
			LsaClose(my_policy_handle);
			pushstring("ERROR RemovePrivileges");
			return;
		}

		LsaClose(my_policy_handle);
		pushstring("OK");
		return;
	}
}


// JPR 020108: Added function HasPrivilege
NSISFunction(HasPrivilege)
{
	PLUGIN_INIT();
	extra->RegisterPluginCallback(g_hInstance, PluginCallback);
	{
		DWORD dwLevel = 1;
		DWORD dwError = 0;
		PSID user_sid;
		LSA_HANDLE my_policy_handle;
		LSA_UNICODE_STRING *lucPrivilege;   
		LSA_UNICODE_STRING *pTmpBuf;
		ULONG count;
		DWORD i;
		NTSTATUS ntStatus;	  

		static char tempbuf[1024];
		static char userid[256];
		static char privilege[256];
		static char privilege2[256];

		static WCHAR u_userid[256];
		static WCHAR u_privilege[256];

		g_hwndParent=hwndParent;

		memset (u_userid,0, sizeof(u_userid));
		memset (u_privilege,0, sizeof(u_privilege));

		popstring(userid);
		swprintf(u_userid, L"%S", userid);

		popstring(privilege);
		swprintf(u_privilege, L"%S", privilege);

		if (EnablePrivilege(SE_RESTORE_NAME)) 
		{
			pushstring("ERROR EnablePrivilege");
			return;
		}

		if (!GetAccountSid(NULL,userid,&user_sid))
		{
			pushstring("ERROR GetAccountSid");
			return;
		}

		my_policy_handle = GetPolicyHandle();

		if (my_policy_handle == NULL)
		{
			pushstring("ERROR GetPolicyHandle");
			return;
		}

		if (ntStatus = LsaEnumerateAccountRights(my_policy_handle, user_sid, (LSA_UNICODE_STRING **) &lucPrivilege, &count) != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(ntStatus);
			if(dwError == ERROR_FILE_NOT_FOUND)sprintf(tempbuf,"FALSE");
			else if(dwError == ERROR_MR_MID_NOT_FOUND)sprintf(tempbuf,"ERROR LsaEnumerateAccountRights n%ld", ntStatus);
			else sprintf(tempbuf,"ERROR LsaEnumerateAccountRights w%lu", dwError);
			if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
			LsaClose(my_policy_handle);
			pushstring(tempbuf);
			return;
		}

		if ((pTmpBuf = lucPrivilege) != NULL)
		{
			for (i = 0; i < count; i++)
			{
				if (pTmpBuf == NULL)
				{
					if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
					LsaClose(my_policy_handle);
					sprintf(userid, "ERROR: An access violation has occurred");
					pushstring(userid);
					return;
				}

				sprintf(privilege2, "%S", pTmpBuf->Buffer);
				if(strcmp(privilege2,privilege) == 0)
				{
					if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
					LsaClose(my_policy_handle);
					pushstring("TRUE");
					return;
				}
				pTmpBuf++;
			}
		}
		if (lucPrivilege != NULL)LsaFreeMemory(&lucPrivilege);
		LsaClose(my_policy_handle);
		pushstring("FALSE");
		return;
	}
}

void ShowError (char *Errormessage)
{
    char buf[1024];
    wsprintf(buf,"%s",Errormessage);

#ifdef _USRDLL
    MessageBox(g_hwndParent,buf,0,MB_OK);
#else
	printf(buf);
#endif

}

#ifdef _USRDLL

#endif