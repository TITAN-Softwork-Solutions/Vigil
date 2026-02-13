use std::{ffi::c_void, mem::size_of, ptr::null_mut};

use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, HWND},
        Security::{
            Cryptography::{
                CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
                CERT_QUERY_OBJECT_FILE, CERT_SHA1_HASH_PROP_ID, CMSG_SIGNER_INFO,
                CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
                CertFreeCertificateContext, CertGetCertificateContextProperty, CertGetNameStringW,
                CryptMsgClose, CryptMsgGetParam, CryptQueryObject, HCERTSTORE, PKCS_7_ASN_ENCODING,
                X509_ASN_ENCODING,
            },
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
                WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
                WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
            },
        },
    },
    core::PCWSTR,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationPolicy {
    None,
    WholeChain,
}

#[derive(Debug, Clone)]
pub struct TrustResult {
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer_subject: Option<String>,
    pub signer_thumbprint: Option<String>,
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn bytes_to_hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

fn extract_signer_identity(path: &str) -> (Option<String>, Option<String>) {
    unsafe {
        let wide = to_wide(path);

        let mut store: HCERTSTORE = HCERTSTORE::default();
        let mut msg: *mut c_void = null_mut();

        let pv_object = wide.as_ptr() as *const c_void;

        let store_out: *mut HCERTSTORE = &mut store;
        let msg_out: *mut *mut c_void = &mut msg;

        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            pv_object,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(store_out),
            Some(msg_out),
            None,
        )
        .is_err()
        {
            return (None, None);
        }

        if msg.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return (None, None);
        }

        let mut signer_info_size: u32 = 0;
        if CryptMsgGetParam(
            msg as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        )
        .is_err()
            || signer_info_size == 0
        {
            let _ = CryptMsgClose(Some(msg as *const c_void));
            let _ = CertCloseStore(Some(store), 0);
            return (None, None);
        }

        let mut buf = vec![0u8; signer_info_size as usize];

        if CryptMsgGetParam(
            msg as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        )
        .is_err()
        {
            let _ = CryptMsgClose(Some(msg as *const c_void));
            let _ = CertCloseStore(Some(store), 0);
            return (None, None);
        }

        let signer_info = &*(buf.as_ptr() as *const CMSG_SIGNER_INFO);

        let mut cert_info = CERT_INFO::default();

        cert_info.Issuer = signer_info.Issuer.clone();
        cert_info.SerialNumber = signer_info.SerialNumber.clone();

        let cert_ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const CERT_INFO as *const c_void),
            None,
        );

        if cert_ctx.is_null() {
            let _ = CryptMsgClose(Some(msg as *const c_void));
            let _ = CertCloseStore(Some(store), 0);
            return (None, None);
        }

        let needed = CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);

        let subject = if needed > 1 {
            let mut name_buf = vec![0u16; needed as usize];
            let got = CertGetNameStringW(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name_buf),
            );
            if got > 1 {
                name_buf.truncate((got - 1) as usize);
                Some(String::from_utf16_lossy(&name_buf))
            } else {
                None
            }
        } else {
            None
        };

        let mut hash_len: u32 = 0;
        let hash_ok = CertGetCertificateContextProperty(
            cert_ctx,
            CERT_SHA1_HASH_PROP_ID,
            None,
            &mut hash_len,
        )
        .is_ok();
        let thumbprint = if hash_ok && hash_len > 0 {
            let mut hash = vec![0u8; hash_len as usize];
            if CertGetCertificateContextProperty(
                cert_ctx,
                CERT_SHA1_HASH_PROP_ID,
                Some(hash.as_mut_ptr() as *mut c_void),
                &mut hash_len,
            )
            .is_ok()
            {
                hash.truncate(hash_len as usize);
                Some(bytes_to_hex_upper(&hash))
            } else {
                None
            }
        } else {
            None
        };

        let _ = CertFreeCertificateContext(Some(cert_ctx));
        let _ = CryptMsgClose(Some(msg as *const c_void));
        let _ = CertCloseStore(Some(store), 0);

        (subject, thumbprint)
    }
}

pub fn verify_file_signature(path: &str, revocation: RevocationPolicy) -> TrustResult {
    unsafe {
        let wide = to_wide(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: Default::default(),
            pgKnownSubject: null_mut(),
        };

        let mut data = WINTRUST_DATA::default();

        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = match revocation {
            RevocationPolicy::None => WTD_REVOKE_NONE,
            RevocationPolicy::WholeChain => WTD_REVOKE_WHOLECHAIN,
        };
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action as *mut _,
            &mut data as *mut _ as *mut c_void,
        );

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action as *mut _,
            &mut data as *mut _ as *mut c_void,
        );

        let is_ok = status == ERROR_SUCCESS.0 as i32;
        let (signer_subject, signer_thumbprint) = extract_signer_identity(path);
        let is_signed = signer_subject.is_some() || signer_thumbprint.is_some();

        TrustResult {
            is_signed,
            is_trusted: is_ok,
            signer_subject,
            signer_thumbprint,
        }
    }
}
