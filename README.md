## SecTor


### Should I rename my buit-in admin account?

Network access validation algorithms and examples for Windows Server 2003, Windows XP, and Windows 2000 (Q103390)   
🔗 https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/network-access-validation-algorithms

Pwd-Properties attribute - Win32 apps | Microsoft Learn  (flag 0x8)   
🔗 https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdproperties 


### Replication metadata

Active Directory Replication Concepts   
🔗 https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts

Metadata #0 - Metadata, what is it and why do we care?   
🔗 https://learn.microsoft.com/en-us/archive/blogs/pie/metadata-0-metadata-what-is-it-and-why-do-we-care


### Time-limited group memberships

Privileged Access Management for Active Directory Domain Services   
🔗 https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services

Add-ADGroupMember -MemberTimeToLive    
🔗 https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2022-ps#-membertimetolive


### Dynamic objects 

Storing Dynamic Data - Win32 apps | Microsoft Learn   
🔗 https://learn.microsoft.com/en-us/windows/win32/ad/storing-dynamic-data 

```
dn: CN=bob2,OU=App1,DC=contoso,DC=com
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: dynamicObject
entryTTL: 1800
cn: bob2
givenName: bob2
distinguishedName: CN=bob2,OU=App1,DC=contoso,DC=com
sAMAccountName: bob2
userPrincipalName: bob2@contoso.com
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=contoso,DC=com
```


### Why can I still use my old password?

New setting modifies NTLM network authentication behavior   
🔗 https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication


### Ban networks from making LDAP calls

3.1.1.3.4.8 LDAP IP-Deny List   
🔗 https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/47e2d581-66c9-430b-bca1-c0a73485fd10


### Audit object modifications

2.2.9 Search Flags  (fNEVERVALUEAUDIT)   
🔗 https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26ff95fb207


### adminSDHolder RTFM

3.1.1.6.1.2 Protected Objects   
🔗 https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0d0b4fa-2895-4c64-b182-ba64ad0f84b8


### Access-Denied Assistance 

Deploy Access-Denied Assistance (Demonstration Steps) | Microsoft Learn   
🔗 https://learn.microsoft.com/en-us/windows-server/identity/solution-guides/deploy-access-denied-assistance--demonstration-steps-


### Restricting logon locations

Authentication Policies and Authentication Policy Silos   
🔗 https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos   

🔗Guidance about how to configure protected accounts   
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts

```PowerShell
New-ADAuthenticationPolicy -Name "Reduced_TGT_120mins" -Description "Authentication policy to set 120 minutes Ticket Granting Ticket." -UserTGTLifetimeMins 120 -Enforce -ProtectedFromAccidentalDeletion $True

New-ADAuthenticationPolicySilo -Name "AdminBoundary" -Description "Authentication policy silo to control the scope of logon for administrators" -UserAuthenticationPolicy "Reduced_TGT_120mins" -ComputerAuthenticationPolicy "Reduced_TGT_120mins" -ServiceAuthenticationPolicy "Reduced_TGT_120mins" -Enforce -ProtectedFromAccidentalDeletion $True

Set-ADAuthenticationPolicy -Identity "Reduced_TGT_120mins" -UserAllowedToAuthenticateFrom 'O:SYG:SYD:(XA;OICI;CR;;;WD; (@USER.ad://ext/AuthenticationSilo == "AdminBoundary"))'

Grant-ADAuthenticationPolicySiloAccess -Identity "AdminBoundary" -Account "CN=Pierre,OU=_Admins,DC=contoso,DC=com"
Grant-ADAuthenticationPolicySiloAccess -Identity "AdminBoundary" -Account "CN=SRV01,CN=Computers,DC=contoso,DC=com"
Grant-ADAuthenticationPolicySiloAccess -Identity "AdminBoundary" -Account "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com"

Get-ADUser -Identity pierre | Set-ADAccountAuthenticationPolicySilo –AuthenticationPolicySilo "AdminBoundary"
Get-ADComputer -Identity SRV01$ | Set-ADAccountAuthenticationPolicySilo –AuthenticationPolicySilo "AdminBoundary"
Get-ADComputer -Identity DC01$ | Set-ADAccountAuthenticationPolicySilo –AuthenticationPolicySilo "AdminBoundary"
```

### Are you still using RDP for admin stuff?

Restricted Admin mode for RDP in Windows 8.1 / 2012 R2   
🔗 https://learn.microsoft.com/en-us/archive/blogs/kfalde/restricted-admin-mode-for-rdp-in-windows-8-1-2012-r2

### Do you still have SMB enumeration enabled?

PowerShell Gallery | NetCease 1.0.3   
🔗 https://www.powershellgallery.com/packages/NetCease/1.0.3



