//! Making Windows trust the CA that signed the broker's certificate.
//!
//! The app's windows are a browser engine, and a browser engine takes its trust from
//! Windows' own certificate store: the settings' `ca_file` is enough for the app's
//! checks but not for a window. So the person can add that one certificate to the
//! Root store of their own Windows account. Windows asks them to confirm, in a dialog
//! of its own that names the certificate and shows its thumbprint; nothing is added
//! unless they say yes there, and the app never adds anything by itself.

/// The certificate in `bytes` (PEM, or DER if it is not PEM) as DER, or `None` if it is
/// not a certificate.
pub fn certificate_der(bytes: &[u8]) -> Option<Vec<u8>> {
    // Windows' PEM reader takes a length of nothing to mean "read up to a zero byte",
    // which an empty file does not have.
    if bytes.is_empty() {
        return None;
    }
    native_tls::Certificate::from_pem(bytes)
        .or_else(|_| native_tls::Certificate::from_der(bytes))
        .and_then(|certificate| certificate.to_der())
        .ok()
}

/// Whether there is something to trust and a point in doing it: the broker is running,
/// the `ca_file` is what makes its certificate verify (so this is the right CA), and
/// Windows itself does not accept it yet.
pub fn worth_offering(running: bool, has_ca: bool, verified: bool, windows_trusts: bool) -> bool {
    running && has_ca && verified && !windows_trusts
}

#[cfg(windows)]
pub use win::add_to_user_roots;

#[cfg(windows)]
mod win {
    use windows::core::w;
    use windows::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreW, HCERTSTORE,
        CERT_STORE_ADD_USE_EXISTING, X509_ASN_ENCODING,
    };

    /// Windows' code for "the person said no" (ERROR_CANCELLED).
    const CANCELLED: u32 = 1223;

    pub(super) fn add(store: HCERTSTORE, der: &[u8]) -> windows::core::Result<()> {
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(store),
                X509_ASN_ENCODING,
                der,
                CERT_STORE_ADD_USE_EXISTING,
                None,
            )
        }
    }

    /// Add the certificate to the Root store of the Windows account this app runs as
    /// (not the whole computer's). Windows shows its own confirmation before it does;
    /// this returns when the person has answered it.
    pub fn add_to_user_roots(der: &[u8]) -> Result<(), String> {
        unsafe {
            let store = CertOpenSystemStoreW(None, w!("ROOT"))
                .map_err(|error| format!("Windows would not open its certificate store: {error}"))?;
            let added = add(store, der);
            let _ = CertCloseStore(Some(store), 0);
            added.map_err(|error| {
                if (error.code().0 as u32) & 0xFFFF == CANCELLED {
                    "The certificate was not added: the Windows confirmation was declined.".to_string()
                } else {
                    format!("Windows did not add the certificate: {error}")
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway certificate made for these tests. Its private key was never kept.
    const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUXvpcbdU1wOLt+zar0q9+CUz6MmwwCgYIKoZIzj0EAwIw
KDEmMCQGA1UEAwwdU3lub2xvZ3kgQnJva2VyIGFwcCB0ZXN0IG9ubHkwIBcNMjYx
MTE0MjIzMTA3WhgPMjEyNjEwMjEyMjMxMDdaMCgxJjAkBgNVBAMMHVN5bm9sb2d5
IEJyb2tlciBhcHAgdGVzdCBvbmx5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
IJWsEBOj4cA6szb5lED0drfJWCfIZU+BXTRTQodFz/UHi9v5IDw8THdetv80ry0Q
NgnMTyhnt6j1gT8VOFZt9KNTMFEwHQYDVR0OBBYEFKO7Mfmt64wNQidc1F+9fmOI
hpgjMB8GA1UdIwQYMBaAFKO7Mfmt64wNQidc1F+9fmOIhpgjMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgRYe8tMcF1QqzKRiCphnHL/5lUu5Fbxf1
hKmLz8cm2GUCIQDiyVbTFCsCb3jvTAaiFZEhBL4rOXiRKqAUx2276KZj5A==
-----END CERTIFICATE-----
";

    #[test]
    fn a_pem_file_and_a_der_file_give_the_same_certificate() {
        let der = certificate_der(PEM.as_bytes()).expect("the PEM certificate was not read");
        // DER starts with a SEQUENCE; this one is 0x1a7 bytes long after its header.
        assert_eq!(&der[..4], &[0x30, 0x82, 0x01, 0xa7]);
        assert_eq!(certificate_der(&der), Some(der));
    }

    #[test]
    fn a_file_that_is_not_a_certificate_is_not_read() {
        assert_eq!(certificate_der(b""), None);
        assert_eq!(certificate_der(b"hello"), None);
        assert_eq!(
            certificate_der(b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"),
            None
        );
    }

    #[test]
    fn trust_is_offered_only_when_it_is_missing_and_would_help() {
        assert!(worth_offering(true, true, true, false));
        // Not running, no ca_file, the ca_file is not what verifies it, or done already.
        assert!(!worth_offering(false, true, true, false));
        assert!(!worth_offering(true, false, true, false));
        assert!(!worth_offering(true, true, false, false));
        assert!(!worth_offering(true, true, true, true));
    }

    /// The same call that adds to Windows' Root store, made on a store that exists only
    /// in this test's memory: nothing on the computer is changed.
    #[cfg(windows)]
    #[test]
    fn the_certificate_goes_into_a_store_and_rubbish_does_not() {
        use windows::Win32::Security::Cryptography::{
            CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
            CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_MEMORY,
        };

        let der = certificate_der(PEM.as_bytes()).unwrap();
        unsafe {
            let store = CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                None,
            )
            .expect("a memory store could not be made");

            assert!(win::add(store, b"not a certificate").is_err());
            assert!(CertEnumCertificatesInStore(store, None).is_null());

            win::add(store, &der).expect("the certificate was refused");
            // Adding it again is not an error and does not make a second copy.
            win::add(store, &der).expect("the same certificate was refused the second time");
            let first = CertEnumCertificatesInStore(store, None);
            assert!(!first.is_null(), "the store is still empty");
            let stored = std::slice::from_raw_parts((*first).pbCertEncoded, (*first).cbCertEncoded as usize);
            assert_eq!(stored, der.as_slice());
            let second = CertEnumCertificatesInStore(store, Some(first));
            assert!(second.is_null(), "the certificate was stored twice");
            if !second.is_null() {
                let _ = CertFreeCertificateContext(Some(second));
            }
            let _ = CertCloseStore(Some(store), 0);
        }
    }
}
