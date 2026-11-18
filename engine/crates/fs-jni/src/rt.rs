// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: golang.org/x/mobile/bind/java/seq_android.c.support (gobind refnum protocol, BSD-3-Clause)

//! Runtime for the gobind object protocol.
//!
//! * Rust ("Go-side") objects are exposed to Java as proxy objects holding a **negative** `int` refnum
//!   (`Seq.trackGoRef` rejects positive ones). When Java garbage-collects a proxy, `Seq.GoRefQueue` calls the
//!   native `Seq.destroyRef(refnum)`. Every proxy object handed to Java gets its own refnum, so each refnum has
//!   exactly one Java owner and `destroyRef` simply drops it; several refnums may share one `Arc`.
//! * Struct classes (`Mark`, `DNSOpts`, …) are Rust-side [`Struct`] values; Kotlin creates them through the
//!   static native `__New()` and accesses fields through native getters/setters.
//! * Errors are thrown as `go.Universe$proxyerror` (exactly what gobind throws) whose `error()` returns the message.
//! * Every export runs inside [`enter`], which contains panics (`catch_unwind`) so they never unwind into the JVM.

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys;
use parking_lot::Mutex;
use std::any::Any;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};

pub type Obj = Arc<dyn Any + Send + Sync>;

/// Error surfaced to Java as `go.Universe$proxyerror`.
#[derive(Debug, Clone)]
pub struct FsError(pub String);

impl FsError {
    pub fn new(msg: impl Into<String>) -> Self {
        FsError(msg.into())
    }
}
impl<E: std::fmt::Display> From<E> for FsError {
    fn from(e: E) -> Self {
        FsError(e.to_string())
    }
}
pub type FsResult<T> = Result<T, FsError>;

// ---------------------------------------------------------------- refnum table

const FIRST_REFNUM: i32 = -42;

struct Table {
    next: i32,
    objs: HashMap<i32, Obj>,
}

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(|| {
        Mutex::new(Table {
            next: FIRST_REFNUM,
            objs: HashMap::new(),
        })
    })
}

/// Allocates a fresh (negative) refnum for `obj`.
pub fn alloc_refnum(obj: Obj) -> i32 {
    let mut t = table().lock();
    loop {
        let r = t.next;
        t.next = if r <= i32::MIN + 1 {
            FIRST_REFNUM
        } else {
            r - 1
        };
        if let std::collections::hash_map::Entry::Vacant(e) = t.objs.entry(r) {
            e.insert(obj);
            return r;
        }
    }
}

pub fn lookup(refnum: i32) -> Option<Obj> {
    table().lock().objs.get(&refnum).cloned()
}

pub fn destroy_ref(refnum: i32) {
    table().lock().objs.remove(&refnum);
}

/// Number of live refnums (exposed for leak checks / `goMet`).
pub fn live_refnums() -> usize {
    table().lock().objs.len()
}

/// Reads the private `int refnum` field of a gobind proxy / struct object.
pub fn refnum_of(env: &mut JNIEnv, obj: &JObject) -> FsResult<i32> {
    if obj.is_null() {
        return Err(FsError::new("null object"));
    }
    Ok(env.get_field(obj, "refnum", "I")?.i()?)
}

/// Resolves a Java proxy / struct object back to its Rust value.
pub fn obj_of<T: Any + Send + Sync>(env: &mut JNIEnv, obj: &JObject) -> FsResult<Arc<T>> {
    let r = refnum_of(env, obj)?;
    let o = lookup(r).ok_or_else(|| FsError::new(format!("unknown refnum {r}")))?;
    o.downcast::<T>()
        .map_err(|_| FsError::new(format!("refnum {r}: unexpected type")))
}

/// Wraps a Rust value in a new Java proxy object of `class` (JNI name, e.g. `com/celzero/firestack/intra/Mark`
/// or `com/celzero/firestack/backend/Backend$proxyIpTree`), whose constructor is `(I)V`.
pub fn new_proxy<'l>(env: &mut JNIEnv<'l>, class: &str, obj: Obj) -> FsResult<JObject<'l>> {
    let r = alloc_refnum(obj);
    match env.new_object(class, "(I)V", &[JValue::Int(r)]) {
        Ok(o) => Ok(o),
        Err(e) => {
            destroy_ref(r);
            Err(e.into())
        }
    }
}

/// Java proxy class implementing a Go-side interface, e.g. `com/celzero/firestack/intra/Tunnel`
/// -> `com/celzero/firestack/intra/Intra$proxyTunnel`.
pub fn proxy_class(iface: &str) -> Option<&'static str> {
    crate::exports::PROXY_CLASSES
        .iter()
        .find(|(i, _)| *i == iface)
        .map(|(_, p)| *p)
}

pub fn new_iface_proxy<'l>(env: &mut JNIEnv<'l>, iface: &str, obj: Obj) -> FsResult<JObject<'l>> {
    let class =
        proxy_class(iface).ok_or_else(|| FsError::new(format!("no proxy class for {iface}")))?;
    new_proxy(env, class, obj)
}

// ---------------------------------------------------------------- struct store

/// A field value of a gobind struct.
#[derive(Clone, Debug, Default)]
pub enum Field {
    #[default]
    Zero,
    Str(String),
    I32(i32),
    I64(i64),
    Bool(bool),
    F64(f64),
    Bytes(Vec<u8>),
    /// Nested struct / Go-side object, with the JNI class used to re-wrap it.
    Obj(&'static str, Obj),
}

/// Rust-side storage of a gobind struct (`Mark`, `DNSOpts`, `DNSSummary`, …).
#[derive(Default)]
pub struct Struct {
    pub class: &'static str,
    fields: Mutex<HashMap<&'static str, Field>>,
}

impl Struct {
    pub fn new(class: &'static str) -> Arc<Self> {
        Arc::new(Struct {
            class,
            fields: Mutex::new(HashMap::new()),
        })
    }
    pub fn get(&self, name: &str) -> Field {
        self.fields.lock().get(name).cloned().unwrap_or_default()
    }
    pub fn set(&self, name: &'static str, v: Field) {
        self.fields.lock().insert(name, v);
    }
    pub fn str(&self, name: &str) -> String {
        match self.get(name) {
            Field::Str(s) => s,
            _ => String::new(),
        }
    }
    pub fn bool(&self, name: &str) -> bool {
        matches!(self.get(name), Field::Bool(true))
    }
    pub fn i64(&self, name: &str) -> i64 {
        match self.get(name) {
            Field::I64(v) => v,
            Field::I32(v) => v as i64,
            _ => 0,
        }
    }
}

/// `__New()` of a struct class: returns the refnum of a fresh zero-valued struct.
pub fn struct_new(class: &'static str) -> i32 {
    alloc_refnum(Struct::new(class))
}

/// Creates a struct and its Java proxy in one go (for values produced by the engine).
pub fn new_struct_object<'l>(env: &mut JNIEnv<'l>, s: Arc<Struct>) -> FsResult<JObject<'l>> {
    let class = s.class;
    new_proxy(env, class, s)
}

pub fn struct_of(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Struct>> {
    obj_of::<Struct>(env, this)
}

// ---------------------------------------------------------------- conversions

pub fn jstr(env: &mut JNIEnv, s: &JString) -> FsResult<String> {
    if s.is_null() {
        return Ok(String::new());
    }
    Ok(env.get_string(s)?.into())
}

pub fn jbytes(env: &mut JNIEnv, a: &JByteArray) -> FsResult<Vec<u8>> {
    if a.is_null() {
        return Ok(Vec::new());
    }
    Ok(env.convert_byte_array(a)?)
}

/// Return-value conversion from Rust to raw JNI, plus Go's zero value used by stubs and on errors.
pub trait Ret<'l>: Sized {
    type Raw;
    fn zero() -> Self::Raw;
    /// Zero value returned to Java when a non-throwing call fails (Go never returns null strings).
    fn zero_env(_env: &mut JNIEnv<'l>) -> Self::Raw {
        Self::zero()
    }
    fn into_raw(self, env: &mut JNIEnv<'l>) -> FsResult<Self::Raw>;
}

impl<'l> Ret<'l> for () {
    type Raw = ();
    fn zero() {}
    fn into_raw(self, _: &mut JNIEnv<'l>) -> FsResult<()> {
        Ok(())
    }
}
impl<'l> Ret<'l> for bool {
    type Raw = sys::jboolean;
    fn zero() -> sys::jboolean {
        sys::JNI_FALSE
    }
    fn into_raw(self, _: &mut JNIEnv<'l>) -> FsResult<sys::jboolean> {
        Ok(if self { sys::JNI_TRUE } else { sys::JNI_FALSE })
    }
}
macro_rules! prim_ret {
    ($t:ty, $raw:ty) => {
        impl<'l> Ret<'l> for $t {
            type Raw = $raw;
            fn zero() -> $raw {
                Default::default()
            }
            fn into_raw(self, _: &mut JNIEnv<'l>) -> FsResult<$raw> {
                Ok(self as $raw)
            }
        }
    };
}
prim_ret!(i32, sys::jint);
prim_ret!(i64, sys::jlong);
prim_ret!(f64, sys::jdouble);
prim_ret!(f32, sys::jfloat);
prim_ret!(i16, sys::jshort);
prim_ret!(i8, sys::jbyte);
prim_ret!(u16, sys::jchar);

impl<'l> Ret<'l> for String {
    type Raw = sys::jstring;
    fn zero() -> sys::jstring {
        std::ptr::null_mut()
    }
    fn zero_env(env: &mut JNIEnv<'l>) -> sys::jstring {
        empty_jstring(env)
    }
    fn into_raw(self, env: &mut JNIEnv<'l>) -> FsResult<sys::jstring> {
        Ok(env.new_string(self)?.into_raw())
    }
}
impl<'l> Ret<'l> for Vec<u8> {
    type Raw = sys::jbyteArray;
    fn zero() -> sys::jbyteArray {
        std::ptr::null_mut()
    }
    fn into_raw(self, env: &mut JNIEnv<'l>) -> FsResult<sys::jbyteArray> {
        Ok(env.byte_array_from_slice(&self)?.into_raw())
    }
}
impl<'l> Ret<'l> for JObject<'l> {
    type Raw = sys::jobject;
    fn zero() -> sys::jobject {
        std::ptr::null_mut()
    }
    fn into_raw(self, _: &mut JNIEnv<'l>) -> FsResult<sys::jobject> {
        Ok(self.into_raw())
    }
}

/// Go returns "" (never null) for strings; stubs and failed non-throwing calls use this.
pub fn empty_jstring(env: &mut JNIEnv) -> sys::jstring {
    env.new_string("")
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

// ---------------------------------------------------------------- errors & entry

fn throw_go_error(env: &mut JNIEnv, msg: &str) {
    if env.exception_check().unwrap_or(false) {
        return; // keep the Java exception already pending
    }
    let err: Obj = Arc::new(msg.to_string());
    match new_proxy(env, "go/Universe$proxyerror", err) {
        Ok(o) => {
            let _ = env.throw(jni::objects::JThrowable::from(o));
        }
        Err(_) => {
            let _ = env.throw_new("java/lang/Exception", msg);
        }
    }
}

/// `go.Universe$proxyerror.error()`
pub fn proxyerror_message(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(obj_of::<String>(env, this)?.as_ref().clone())
}

/// Runs one native call: contains panics, maps errors to Java exceptions (when the Java method declares
/// `throws Exception`) or to Go's zero value (otherwise; logged), and converts the return value.
///
/// # Safety
/// `raw` must be the `JNIEnv*` the JVM passed to the current native method, used on that same thread.
pub unsafe fn enter<'l, R, F>(
    raw: *mut sys::JNIEnv,
    what: &'static str,
    throws: bool,
    f: F,
) -> R::Raw
where
    R: Ret<'l>,
    F: FnOnce(&mut JNIEnv<'l>) -> FsResult<R>,
{
    // SAFETY: called from a JNI export with the env pointer the JVM handed us.
    let mut env = match unsafe { JNIEnv::from_raw(raw) } {
        Ok(e) => e,
        Err(_) => return R::zero(),
    };
    let res = catch_unwind(AssertUnwindSafe(|| f(&mut env)));
    let err = match res {
        Ok(Ok(v)) => match v.into_raw(&mut env) {
            Ok(raw) => return raw,
            Err(e) => e,
        },
        Ok(Err(e)) => e,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".into());
            crate::impls::log::crash(what, &msg);
            FsError(format!("panic in {what}: {msg}"))
        }
    };
    if throws {
        throw_go_error(&mut env, &err.0);
    } else {
        crate::impls::log::warn(&format!("{what}: {}", err.0));
    }
    R::zero_env(&mut env)
}

/// Body of a not-yet-ported native.
pub fn unimplemented<T>(what: &'static str) -> FsResult<T> {
    Err(FsError(format!(
        "unimplemented in RethinkReloaded rust engine: {what}"
    )))
}

/// Body of an RPN native (RPN is not offered by RethinkReloaded).
pub fn rpn_unsupported<T>(what: &'static str) -> FsResult<T> {
    Err(FsError(format!(
        "rpn: unsupported in RethinkReloaded: {what}"
    )))
}

/// Zero value with Go semantics for stubs of non-throwing methods.
pub fn zero_value<'l, R: Ret<'l> + GoZero>() -> FsResult<R> {
    Ok(R::go_zero())
}

/// Go zero values as Rust values (strings are "", objects null).
pub trait GoZero {
    fn go_zero() -> Self;
}
impl GoZero for () {
    fn go_zero() {}
}
impl GoZero for bool {
    fn go_zero() -> bool {
        false
    }
}
macro_rules! num_zero { ($($t:ty),*) => { $(impl GoZero for $t { fn go_zero() -> $t { 0 as $t } })* } }
num_zero!(i8, i16, i32, i64, u16, f32, f64);
impl GoZero for String {
    fn go_zero() -> String {
        String::new()
    }
}
impl GoZero for Vec<u8> {
    fn go_zero() -> Vec<u8> {
        Vec::new()
    }
}
impl GoZero for JObject<'_> {
    fn go_zero() -> Self {
        JObject::null()
    }
}

/// Helper so generated code can ignore an unused `this`/class argument uniformly.
pub fn ignore_class(_: JClass) {}

// ---------------------------------------------------------------- struct field helpers (used by exports.rs)

pub fn field_f64(s: &Struct, name: &str) -> f64 {
    match s.get(name) {
        Field::F64(v) => v,
        Field::I64(v) => v as f64,
        Field::I32(v) => v as f64,
        _ => 0.0,
    }
}

pub fn field_bytes(s: &Struct, name: &str) -> Vec<u8> {
    match s.get(name) {
        Field::Bytes(v) => v,
        _ => Vec::new(),
    }
}

/// Getter of a struct field holding a nested struct / Go-side object: wraps it in a new Java proxy, or null.
pub fn field_obj<'l>(env: &mut JNIEnv<'l>, s: &Struct, name: &str) -> FsResult<JObject<'l>> {
    match s.get(name) {
        Field::Obj(class, o) => new_proxy(env, class, o),
        _ => Ok(JObject::null()),
    }
}

/// Setter of a struct field holding a nested struct / Go-side object (Java passes its proxy).
pub fn set_field_obj(
    env: &mut JNIEnv,
    s: &Struct,
    name: &'static str,
    v: &JObject,
) -> FsResult<()> {
    if v.is_null() {
        s.set(name, Field::Zero);
        return Ok(());
    }
    let r = refnum_of(env, v)?;
    let o = lookup(r).ok_or_else(|| FsError::new(format!("unknown refnum {r}")))?;
    let class: &'static str = match o.downcast_ref::<Struct>() {
        Some(st) => st.class,
        None => return Err(FsError::new("only struct-valued fields are supported")),
    };
    s.set(name, Field::Obj(class, o));
    Ok(())
}
