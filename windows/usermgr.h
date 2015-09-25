/**

  **/

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <ntsecapi.h>
#include <windef.h>


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif


BOOL InitLsaString(  PLSA_UNICODE_STRING pLsaString,  LPCWSTR pwszString );
LSA_HANDLE GetPolicyHandle();
NTSTATUS AddPrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege);
NTSTATUS RemovePrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle, LSA_UNICODE_STRING lucPrivilege);
BOOL GetAccountSid(LPTSTR SystemName, LPTSTR AccountName, PSID *Sid);

