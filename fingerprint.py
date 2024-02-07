import ctypes
from ctypes import wintypes

SECURITY_MAX_SID_SIZE = 68
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_ID_TYPE_SID = 3
WINBIO_E_NO_MATCH = 0x80098005

lib = ctypes.WinDLL(r"C:\Windows\System32\winbio.dll")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class AccountSid(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("Data", ctypes.c_ubyte * SECURITY_MAX_SID_SIZE),
    ]


class Value(ctypes.Union):
    _fields_ = [
        ("NULL", wintypes.ULONG),
        ("Wildcard", wintypes.ULONG),
        ("TemplateGuid", GUID),
        ("AccountSid", AccountSid),
    ]


class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_uint32), ("Value", Value)]


class TOKEN_INFORMATION_CLASS:
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", wintypes.BYTE * 6)]


class SID(ctypes.Structure):
    _fields_ = [
        ("Revision", wintypes.BYTE),
        ("SubAuthorityCount", wintypes.BYTE),
        ("IdentifierAuthority", SID_IDENTIFIER_AUTHORITY),
        ("SubAuthority", wintypes.DWORD),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.POINTER(SID)), ("Attributes", wintypes.DWORD)]


class TOEKN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


def open_session():
    session_handle = ctypes.c_uint32()
    ret = lib.WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,
        WINBIO_POOL_SYSTEM,
        WINBIO_FLAG_DEFAULT,
        None,
        0,
        None,
        ctypes.byref(session_handle),
    )
    if ret & 0xFFFFFFFF != 0x0:
        print("Open Failed!")
        return None
    return session_handle


def locate_unit(session_handle):
    unit_id = ctypes.c_uint32()
    ret = lib.WinBioLocateSensor(session_handle, ctypes.byref(unit_id))
    if ret & 0xFFFFFFFF != 0x0:
        print("Locate Failed!")
        return None
    return unit_id


def identify(session_handle, unit_id):
    subfactor = ctypes.c_ubyte(0xF5)
    identity = WINBIO_IDENTITY()
    reject_detail = ctypes.c_uint32()
    ret = lib.WinBioIdentify(
        session_handle,
        ctypes.byref(unit_id),
        ctypes.byref(identity),
        ctypes.byref(subfactor),
        ctypes.byref(reject_detail),
    )
    if ret & 0xFFFFFFFF != 0x0:
        print(hex(ret & 0xFFFFFFFF))
        raise Exception("Identify Error")
    print(f"Unit ID\t:{hex(unit_id.value)}")
    print(f"Sub Factor\t:{hex(subfactor.value)}")
    print(f"Identity Type\t: {identity.Type}")
    print(
        f"Identity AccountSid Data\t: {list(identity.Value.AccountSid.Data)[0:identity.Value.AccountSid.Size]}"
    )
    print(f"Identity AccountSid Size\t: {identity.Value.AccountSid.Size}")
    print(f"Rejected Details:\t{hex(reject_detail.value)}")


def verify(session_handle, unit_id, subfactor, identity):
    match = ctypes.c_bool(0)
    reject_detail = ctypes.c_uint32()
    get_current_user_identity(identity)
    ret = lib.WinBioVerify(
        session_handle,
        ctypes.byref(identity),
        subfactor,
        ctypes.byref(subfactor),
        ctypes.byref(match),
        ctypes.byref(reject_detail),
    )
    if ret & 0xFFFFFFFF == WINBIO_E_NO_MATCH or ret & 0xFFFFFFFF == 0:
        return match.value
    else:
        print(hex(ret & 0xFFFFFFFF))
        raise Exception("Identify Error")


def close_session(session_handle):
    lib.WinBioCloseSession(session_handle)


def get_process_token():
    GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE
    OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
    OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    OpenProcessToken.restype = wintypes.BOOL
    token = wintypes.HANDLE()

    TOKEN_READ = 0x20008
    res = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, token)
    if not res > 0:
        raise RuntimeError("Couldn't get process token")
    return token


def get_token_information(identity):
    GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
    GetTokenInformation.argtypes = [
        wintypes.HANDLE,  # TokenHandle
        ctypes.c_uint,  # TOKEN_INFORMATION_CLASS value
        wintypes.LPVOID,  # TokenInformation
        wintypes.DWORD,  # TokenInformationLength
        ctypes.POINTER(wintypes.DWORD),  # ReturnLength
    ]
    GetTokenInformation.restype = wintypes.BOOL

    CopySid = ctypes.windll.advapi32.CopySid
    CopySid.argtypes = [
        wintypes.DWORD,  # nDestinationSidLength
        ctypes.c_void_p,  # pDestinationSid,
        ctypes.c_void_p,  # pSourceSid
    ]
    CopySid.restype = wintypes.BOOL

    GetLengthSid = ctypes.windll.advapi32.GetLengthSid
    GetLengthSid.argtypes = [ctypes.POINTER(SID)]  # PSID
    GetLengthSid.restype = wintypes.DWORD

    return_length = wintypes.DWORD(0)
    buffer = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)

    res = GetTokenInformation(
        get_process_token(),
        TOKEN_INFORMATION_CLASS.TokenUser,
        buffer,
        SECURITY_MAX_SID_SIZE,
        ctypes.byref(return_length),
    )
    assert res > 0, "Error in second GetTokenInformation (%d)" % res

    token_user = ctypes.cast(buffer, ctypes.POINTER(TOEKN_USER)).contents
    CopySid(SECURITY_MAX_SID_SIZE, identity.Value.AccountSid.Data, token_user.User.Sid)
    identity.Type = WINBIO_ID_TYPE_SID
    identity.Value.AccountSid.Size = GetLengthSid(token_user.User.Sid)


def get_current_user_identity(identity):
    get_token_information(identity)


# if __name__ == '__main__':
#     session_handle = None
#     try:
#         session_handle = open_session()
#         if session_handle:
#             unit_id = locate_unit(session_handle)
#             if unit_id:
#                 print("Please touch the fingerprint sensor")
#                 identity = WINBIO_IDENTITY()  # Initialize identity here
#                 if verify(session_handle, unit_id, ctypes.c_ubyte(0xf5), identity):
#                     print("Hello! Master")
#                 else:
#                     print("Sorry! Man")
#     finally:
#         if session_handle:
#             close_session(session_handle)
