using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class Impersonate : IDisposable
{
    // ����́Aenum �Œ�`����ׂ��B�B�B
    private static int LOGON32_LOGON_INTERACTIVE = 2;
    private static int LOGON32_PROVIDER_DEFAULT = 0;
    private WindowsImpersonationContext impersonationContext;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    private extern static bool DuplicateToken(
        IntPtr ExistingTokenHandle,
        int SECURITY_IMPERSONATION_LEVEL,
        out IntPtr DuplicateTokenHandle
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private Impersonate(WindowsIdentity tempWindowsIdentity)
    {
        impersonationContext = tempWindowsIdentity.Impersonate();
    }

    public static Impersonate ImpersonateValidUser(string userName, string domain, string password)
    {
        WindowsIdentity tempWindowsIdentity;
        IntPtr token = IntPtr.Zero;
        IntPtr tokenDuplicate = IntPtr.Zero;
        Impersonate retValue = null;
        try {
            // ���݋U�����Ă��Ȃ����Ƃ��m�F�B
            if (RevertToSelf() == true) {
                // �U�����郆�[�U�[�̃��[�U�[���ƃp�X���[�h���m�F�B
                if (LogonUser(userName, domain, password,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out token) == true) {
                    // ���݃��O�C�����̃��[�U�[�̃R���e�L�X�g�𕡐�����B
                    if (DuplicateToken(token, 2, out tokenDuplicate) == true) {
                        tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                        retValue = new Impersonate(tempWindowsIdentity);
                        if (retValue.impersonationContext == null) {
                            retValue = null;
                        }
                    }
                }
            }
            return retValue;
        }
        finally
        {
            // try - finally �͂Q�d�ɂ���ׂ��B�B�B
            if (!tokenDuplicate.Equals(IntPtr.Zero))
            {
                CloseHandle(tokenDuplicate);
            }
            if (!token.Equals(IntPtr.Zero))
            {
                CloseHandle(token);
            }
        }
    }

    public virtual void Dispose()
    {
        if (impersonationContext != null)
        {
            // �U������������B
            impersonationContext.Undo();
            impersonationContext = null;
        }
    }

    ~Impersonate()
    {
        this.Dispose();
    }
}

[TestClass]
public class ImpersonateTest
{
    [TestMethod]
    public void DoImpersonate()
    {
        Impersonate impersonate = null;
        try {
            impersonate = Impersonate.ImpersonateValidUser("yukaritester", "WXP0148D51", "123456");
            if (impersonate != null)
                Console.WriteLine("Impersonated.");
        } finally {
            if (impersonate != null)
                impersonate.Dispose();
        }
    }
}