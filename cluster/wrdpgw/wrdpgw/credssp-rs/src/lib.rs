/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 */

// CredSSP token computation for wrdpgw secretless access.
//
// This library deliberately performs no socket I/O. It is a pure state machine:
// Go owns the upstream TLS connection and pumps each TSRequest in and out, while
// this side computes the next token using the injected credentials. That keeps
// the FFI surface on the control path (a handful of calls during the handshake)
// rather than the data path, so there is no long-lived shared stream to race a
// close against and no per-chunk crossing during the session.
//
// Scope for v1 is NTLM only. Negotiate/Kerberos would make sspi yield KDC
// network requests; resolve_to_result surfaces that as an error rather than
// silently failing, which is the intended typed signal until KDC proxying lands.

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, TsRequest};
use sspi::ntlm::NtlmConfig;
use sspi::{AuthIdentity, Credentials, Secret, Username};

const WRDPGW_OK: i32 = 0;
const WRDPGW_ERR_INVALID_ARGUMENT: i32 = 1;
const WRDPGW_ERR_CREDSSP: i32 = 5;
#[allow(dead_code)]
const WRDPGW_ERR_KERBEROS_KDC_REQUIRED: i32 = 6;
#[allow(dead_code)]
const WRDPGW_ERR_AUTH_FAILED: i32 = 7;
const WRDPGW_ERR_INTERNAL: i32 = 255;

const CREDSSP_STATE_REPLY_NEEDED: i32 = 0;
const CREDSSP_STATE_FINAL: i32 = 1;

pub struct WrdpgwCredssp {
    client: CredSspClient,
}

#[no_mangle]
pub unsafe extern "C" fn wrdpgw_credssp_new(
    server_pubkey: *const u8,
    server_pubkey_len: usize,
    domain: *const u8,
    domain_len: usize,
    username: *const u8,
    username_len: usize,
    password: *const u8,
    password_len: usize,
    target: *const u8,
    target_len: usize,
    out_client: *mut *mut WrdpgwCredssp,
    out_error: *mut *mut c_char,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        new_impl(
            server_pubkey,
            server_pubkey_len,
            domain,
            domain_len,
            username,
            username_len,
            password,
            password_len,
            target,
            target_len,
        )
    }));
    eprintln!("wrdpgw_credssp_new: public_key_len={} head={:02x?} domain_len={} user_len={} target_len={}", server_pubkey_len, if server_pubkey_len > 0 { Some(*server_pubkey) } else { None }, domain_len, username_len, target_len);

    if !out_client.is_null() {
        *out_client = ptr::null_mut();
    }

    match res {
        Ok(Ok(client)) => {
            eprintln!("wrdpgw_credssp_new: created client");
            if out_client.is_null() {
                eprintln!("wrdpgw_credssp_new: out_client is null");
                return WRDPGW_ERR_INVALID_ARGUMENT;
            }
            *out_client = Box::into_raw(Box::new(client));
            WRDPGW_OK
        }
        Ok(Err((kind, msg))) => {
            eprintln!("wrdpgw_credssp_new: error {}: {}", kind, msg);
            set_error(out_error, &msg);
            kind
        }
        Err(_) => {
            eprintln!("wrdpgw_credssp_new: panic");
            set_error(out_error, "panic in wrdpgw_credssp_new");
            WRDPGW_ERR_INTERNAL
        }
    }
}

unsafe fn new_impl(
    server_pubkey: *const u8,
    server_pubkey_len: usize,
    domain: *const u8,
    domain_len: usize,
    username: *const u8,
    username_len: usize,
    password: *const u8,
    password_len: usize,
    target: *const u8,
    target_len: usize,
) -> Result<WrdpgwCredssp, (i32, String)> {
    let pubkey = match bytes(server_pubkey, server_pubkey_len) {
        Some(b) if !b.is_empty() => b.to_vec(),
        _ => return Err((WRDPGW_ERR_INVALID_ARGUMENT, "missing server public key".into())),
    };

    let domain = utf8(domain, domain_len)
        .map_err(|_| (WRDPGW_ERR_INVALID_ARGUMENT, "invalid domain encoding".to_string()))?;
    let username = utf8(username, username_len)
        .map_err(|_| (WRDPGW_ERR_INVALID_ARGUMENT, "invalid username encoding".to_string()))?;
    if username.is_empty() {
        return Err((WRDPGW_ERR_INVALID_ARGUMENT, "missing username".into()));
    }
    let password = utf8(password, password_len)
        .map_err(|_| (WRDPGW_ERR_INVALID_ARGUMENT, "invalid password encoding".to_string()))?;
    let target = utf8(target, target_len)
        .map_err(|_| (WRDPGW_ERR_INVALID_ARGUMENT, "invalid target encoding".to_string()))?;

    let uname = Username::new(&username, if domain.is_empty() { None } else { Some(&domain) })
        .map_err(|e| (WRDPGW_ERR_INVALID_ARGUMENT, format!("invalid username: {e}")))?;

    let identity = AuthIdentity {
        username: uname,
        password: Secret::from(password),
    };
    eprintln!("wrdpgw_credssp_new: creating CredSspClient for user {} domain {} target {}", username, domain, target);

    let client = CredSspClient::new(
        pubkey,
        Credentials::AuthIdentity(identity),
        CredSspMode::WithCredentials,
        ClientMode::Ntlm(NtlmConfig::default()),
        target,
    )
    .map_err(|e| (WRDPGW_ERR_CREDSSP, format!("credssp init: {e}")))?;
    eprintln!("wrdpgw_credssp_new: initialized CredSspClient for user {} domain {} target {}", username, domain, target);

    Ok(WrdpgwCredssp { client })
}

#[no_mangle]
pub unsafe extern "C" fn wrdpgw_credssp_step(
    client: *mut WrdpgwCredssp,
    incoming: *const u8,
    incoming_len: usize,
    out_outgoing: *mut *mut u8,
    out_outgoing_len: *mut usize,
    out_state: *mut i32,
    out_error: *mut *mut c_char,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| step_impl(client, incoming, incoming_len)));
    eprintln!("wrdpgw_credssp_step: incoming_len={} out_outgoing={:?} out_outgoing_len={:?} out_state={:?}", incoming_len, out_outgoing, out_outgoing_len, out_state);
    match res {
        Ok(Ok((buf, state))) => {
            eprintln!("wrdpgw_credssp_step: outgoing_len={} state={}", buf.len(), state);
            let (p, l) = leak_bytes(buf);
            if !out_outgoing.is_null() {
                *out_outgoing = p;
            }
            if !out_outgoing_len.is_null() {
                *out_outgoing_len = l;
            }
            if !out_state.is_null() {
                *out_state = state;
            }
            WRDPGW_OK
        }
        Ok(Err((kind, msg))) => {
            eprintln!("wrdpgw_credssp_step: error {}: {}", kind, msg);
            set_error(out_error, &msg);
            kind
        }
        Err(_) => {
            set_error(out_error, "panic in wrdpgw_credssp_step");
            WRDPGW_ERR_INTERNAL
        }
    }
}

unsafe fn step_impl(
    client: *mut WrdpgwCredssp,
    incoming: *const u8,
    incoming_len: usize,
) -> Result<(Vec<u8>, i32), (i32, String)> {
    if client.is_null() {
        return Err((WRDPGW_ERR_INVALID_ARGUMENT, "null client".into()));
    }
    let client = &mut *client;

    let ts_request = if incoming_len == 0 {
        TsRequest::default()
    } else {
        let b = bytes(incoming, incoming_len)
            .ok_or((WRDPGW_ERR_INVALID_ARGUMENT, "null incoming buffer".to_string()))?;
        TsRequest::from_buffer(b)
            .map_err(|e| (WRDPGW_ERR_CREDSSP, format!("decode TSRequest: {e}")))?
    };

    let state = client
        .client
        .process(ts_request)
        .resolve_to_result()
        .map_err(|e| (WRDPGW_ERR_CREDSSP, format!("credssp: {e}")))?;

    let (req, st) = match state {
        ClientState::ReplyNeeded(req) => (req, CREDSSP_STATE_REPLY_NEEDED),
        ClientState::FinalMessage(req) => (req, CREDSSP_STATE_FINAL),
    };
    eprintln!("wrdpgw_credssp_step: incoming_len={} state={}", incoming_len, st);

    let mut buf = Vec::with_capacity(req.buffer_len() as usize);
    req.encode_ts_request(&mut buf)
        .map_err(|e| (WRDPGW_ERR_CREDSSP, format!("encode TSRequest: {e}")))?;

    eprintln!("wrdpgw_credssp_step: outgoing_len={} state={}", buf.len(), st);

    Ok((buf, st))
}

#[no_mangle]
pub unsafe extern "C" fn wrdpgw_credssp_free(client: *mut WrdpgwCredssp) {
    if client.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(client));
    }));
}

#[no_mangle]
pub unsafe extern "C" fn wrdpgw_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Vec::from_raw_parts(ptr, len, len));
}

#[no_mangle]
pub unsafe extern "C" fn wrdpgw_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(p, len))
}

unsafe fn utf8(p: *const u8, len: usize) -> Result<String, ()> {
    let b = bytes(p, len).ok_or(())?;
    std::str::from_utf8(b).map(|s| s.to_owned()).map_err(|_| ())
}

unsafe fn set_error(out_error: *mut *mut c_char, msg: &str) {
    if out_error.is_null() {
        return;
    }
    *out_error = CString::new(msg).map(|c| c.into_raw()).unwrap_or(ptr::null_mut());
}

fn leak_bytes(v: Vec<u8>) -> (*mut u8, usize) {
    let boxed = v.into_boxed_slice();
    let len = boxed.len();
    let p = Box::into_raw(boxed) as *mut u8;
    (p, len)
}