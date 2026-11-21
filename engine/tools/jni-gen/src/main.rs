// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! jni-gen: emits `crates/fs-jni/src/exports.rs` from `api/natives.tsv` (written by `tools/facade-sync.sh`) and
//! `crates/fs-jni/impls.tsv` (hand-maintained list of natives with real Rust implementations).
//!
//! Usage (from engine/): `cargo run -p jni-gen` ; `cargo run -p jni-gen -- --check` fails if exports.rs is stale;
//! `--list-stubs` prints the natives that are still stubs (class, method) to stderr.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs, process};

struct Native {
    class: String, // dotted, e.g. com.celzero.firestack.intra.Intra$proxyTunnel
    method: String,
    params: Vec<String>, // JNI type descriptors
    ret: String,
    is_static: bool,
    throws: bool,
}

fn parse_desc(d: &str) -> (Vec<String>, String) {
    let inner = &d[1..d.find(')').expect("descriptor")];
    let ret = d[d.find(')').unwrap() + 1..].to_string();
    let b = inner.as_bytes();
    let (mut i, mut out) = (0, vec![]);
    while i < b.len() {
        let start = i;
        while b[i] == b'[' {
            i += 1;
        }
        if b[i] == b'L' {
            while b[i] != b';' {
                i += 1;
            }
        }
        i += 1;
        out.push(inner[start..i].to_string());
    }
    (out, ret)
}

/// JNI short-name mangling of one identifier component.
fn mangle(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '.' | '/' => o.push('_'),
            '_' => o.push_str("_1"),
            ';' => o.push_str("_2"),
            '[' => o.push_str("_3"),
            c if c.is_ascii_alphanumeric() => o.push(c),
            c => {
                let _ = write!(o, "_0{:04x}", c as u32);
            }
        }
    }
    o
}

fn jni_class(dotted: &str) -> String {
    dotted.replace('.', "/")
}

fn simple(class: &str) -> &str {
    let s = class.rsplit('.').next().unwrap();
    s.rsplit("$proxy").next().unwrap()
}

/// Raw JNI parameter type.
fn raw_ty(d: &str) -> &'static str {
    match d {
        "Z" => "sys::jboolean",
        "B" => "sys::jbyte",
        "C" => "sys::jchar",
        "S" => "sys::jshort",
        "I" => "sys::jint",
        "J" => "sys::jlong",
        "F" => "sys::jfloat",
        "D" => "sys::jdouble",
        "Ljava/lang/String;" => "sys::jstring",
        "[B" => "sys::jbyteArray",
        _ => "sys::jobject",
    }
}

/// Rust value type handed to implementations / returned by them.
fn rust_ty(d: &str) -> &'static str {
    match d {
        "V" => "()",
        "Z" => "bool",
        "B" => "i8",
        "C" => "u16",
        "S" => "i16",
        "I" => "i32",
        "J" => "i64",
        "F" => "f32",
        "D" => "f64",
        "Ljava/lang/String;" => "String",
        "[B" => "Vec<u8>",
        _ => "JObject<'l>",
    }
}

fn raw_ret(d: &str) -> &'static str {
    match d {
        "V" => "()",
        "Z" => "sys::jboolean",
        "B" => "sys::jbyte",
        "C" => "sys::jchar",
        "S" => "sys::jshort",
        "I" => "sys::jint",
        "J" => "sys::jlong",
        "F" => "sys::jfloat",
        "D" => "sys::jdouble",
        "Ljava/lang/String;" => "sys::jstring",
        "[B" => "sys::jbyteArray",
        _ => "sys::jobject",
    }
}

fn convert_arg(d: &str, name: &str) -> String {
    match d {
        "Z" => format!("let {name} = {name} != 0;"),
        "Ljava/lang/String;" => {
            format!("let {name} = rt::jstr(env, &unsafe {{ JString::from_raw({name}) }})?;")
        }
        "[B" => {
            format!("let {name} = rt::jbytes(env, &unsafe {{ JByteArray::from_raw({name}) }})?;")
        }
        d if d.starts_with('L') || d.starts_with('[') => {
            format!("let {name} = unsafe {{ JObject::from_raw({name}) }};")
        }
        _ => String::new(),
    }
}

fn is_rpn(n: &Native) -> bool {
    let s = simple(&n.class);
    let m = n.method.to_ascii_lowercase();
    s.starts_with("Rpn")
        || s.starts_with("Pip")
        || (s == "Backend" && (m.contains("pip") || m.contains("rpn") || m == "token"))
        || (s == "Proxies" && m == "rpn")
}

fn struct_body(n: &Native) -> Option<String> {
    let jc = jni_class(&n.class);
    if n.method == "__New" {
        return Some(format!("Ok(rt::struct_new(\"{jc}\"))"));
    }
    if let Some(field) = n.method.strip_prefix("get")
        && n.params.is_empty()
        && n.ret != "V"
    {
        {
            let getter = match n.ret.as_str() {
                "Ljava/lang/String;" => format!("Ok(s.str(\"{field}\"))"),
                "Z" => format!("Ok(s.bool(\"{field}\"))"),
                "J" => format!("Ok(s.i64(\"{field}\"))"),
                "I" => format!("Ok(s.i64(\"{field}\") as i32)"),
                "D" => format!("Ok(rt::field_f64(&s, \"{field}\"))"),
                "F" => format!("Ok(rt::field_f64(&s, \"{field}\") as f32)"),
                "[B" => format!("Ok(rt::field_bytes(&s, \"{field}\"))"),
                _ => format!("rt::field_obj(env, &s, \"{field}\")"),
            };
            return Some(format!("let s = rt::struct_of(env, &this)?; {getter}"));
        }
    }
    if let Some(field) = n.method.strip_prefix("set")
        && n.params.len() == 1
        && n.ret == "V"
    {
        {
            let setter = match n.params[0].as_str() {
                "Ljava/lang/String;" => format!("s.set(\"{field}\", rt::Field::Str(a0));"),
                "Z" => format!("s.set(\"{field}\", rt::Field::Bool(a0));"),
                "J" => format!("s.set(\"{field}\", rt::Field::I64(a0));"),
                "I" => format!("s.set(\"{field}\", rt::Field::I32(a0));"),
                "D" => format!("s.set(\"{field}\", rt::Field::F64(a0));"),
                "F" => format!("s.set(\"{field}\", rt::Field::F64(a0 as f64));"),
                "[B" => format!("s.set(\"{field}\", rt::Field::Bytes(a0));"),
                _ => format!("rt::set_field_obj(env, &s, \"{field}\", &a0)?;"),
            };
            return Some(format!(
                "let s = rt::struct_of(env, &this)?; {setter} Ok(())"
            ));
        }
    }
    None
}

fn runtime_body(n: &Native) -> Option<&'static str> {
    Some(match (n.class.as_str(), n.method.as_str()) {
        ("go.Seq", "init") => "crate::impls::seq::init(env)",
        ("go.Seq", "setContext") => "crate::impls::seq::set_context(env, a0)",
        // Rust reads the `refnum` field of proxies directly and gives each Java proxy its own refnum,
        // so the gobind Go-side reference counting is not needed.
        ("go.Seq", "incGoRef") => "Ok(())",
        ("go.Seq", "destroyRef") => "{ rt::destroy_ref(a0); Ok(()) }",
        ("go.Universe$proxyerror", "error") => "rt::proxyerror_message(env, &this)",
        (_, "_init") => "Ok(())",
        _ => return None,
    })
}

fn main() {
    let check = env::args().any(|a| a == "--check");
    let symbols = env::args().any(|a| a == "--symbols");
    let list_stubs = env::args().any(|a| a == "--list-stubs");
    let engine = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tsv = fs::read_to_string(engine.join("api/natives.tsv"))
        .expect("api/natives.tsv (run tools/facade-sync.sh)");
    let pin = fs::read_to_string(engine.join("api/PIN"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let impls_path = engine.join("crates/fs-jni/impls.tsv");
    let impls_src = fs::read_to_string(&impls_path).unwrap_or_default();

    let natives: Vec<Native> = tsv
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let (params, ret) = parse_desc(f[2]);
            Native {
                class: f[0].into(),
                method: f[1].into(),
                params,
                ret,
                is_static: f[3] == "1",
                throws: f[4] == "1",
            }
        })
        .collect();

    let mut impls: BTreeMap<(String, String), String> = BTreeMap::new();
    for l in impls_src
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let f: Vec<&str> = l.split('\t').filter(|s| !s.is_empty()).collect();
        assert!(
            f.len() == 3,
            "impls.tsv: expected class<TAB>method<TAB>rust_path: {l}"
        );
        impls.insert((f[0].into(), f[1].into()), f[2].into());
    }
    let known: BTreeSet<(String, String)> = natives
        .iter()
        .map(|n| (n.class.clone(), n.method.clone()))
        .collect();
    let stale: Vec<_> = impls.keys().filter(|k| !known.contains(*k)).collect();
    if !stale.is_empty() {
        eprintln!(
            "impls.tsv lists natives that no longer exist in the facade (API drift): {stale:?}"
        );
        process::exit(1);
    }

    let structs: BTreeSet<&str> = natives
        .iter()
        .filter(|n| n.method == "__New")
        .map(|n| n.class.as_str())
        .collect();

    let mut proxies: BTreeMap<String, String> = BTreeMap::new();
    for n in &natives {
        if let Some((outer, iface)) = n.class.split_once("$proxy") {
            let pkg = &outer[..outer.rfind('.').unwrap()];
            proxies.insert(jni_class(&format!("{pkg}.{iface}")), jni_class(&n.class));
        }
    }

    let mut o = String::new();
    let _ = writeln!(
        o,
        "// @generated by engine/tools/jni-gen from api/natives.tsv (firestack@{pin}). DO NOT EDIT."
    );
    let _ = writeln!(
        o,
        "// Copyright (c) 2026 RethinkReloaded contributors. SPDX-License-Identifier: MPL-2.0"
    );
    o.push_str(
        "#![allow(unused_variables, unused_mut, unused_unsafe, non_snake_case, clippy::all)]\n",
    );
    o.push_str(
        "use crate::rt;\nuse jni::objects::{JByteArray, JObject, JString};\nuse jni::sys;\n\n",
    );
    let _ = writeln!(o, "pub const FIRESTACK_PIN: &str = \"{pin}\";");
    let _ = writeln!(o, "pub const NATIVE_COUNT: usize = {};", natives.len());
    let (mut n_impl, mut n_struct, mut n_rt, mut n_rpn, mut n_stub) = (0, 0, 0, 0, 0);

    o.push_str("/// (Go-side interface, Java proxy class) pairs, JNI names.\npub const PROXY_CLASSES: &[(&str, &str)] = &[\n");
    for (i, p) in &proxies {
        let _ = writeln!(o, "    (\"{i}\", \"{p}\"),");
    }
    o.push_str("];\n\n/// gobind struct classes (JNI names), instantiated by the engine via `(I)V`.\npub const STRUCT_CLASSES: &[&str] = &[\n");
    for c in &structs {
        let _ = writeln!(o, "    \"{}\",", jni_class(c));
    }
    o.push_str("];\n\n/// Exported JNI symbol of every native (for completeness tests).\npub const NATIVE_SYMBOLS: &[&str] = &[\n");
    let sym = |n: &Native| format!("Java_{}_{}", mangle(&n.class), mangle(&n.method));
    for n in &natives {
        let _ = writeln!(o, "    \"{}\",", sym(n));
    }
    o.push_str("];\n\n");

    for n in &natives {
        let what = format!("{}.{}", simple_outer(&n.class), n.method);
        let mut params = String::from("env: *mut sys::JNIEnv, ");
        params.push_str(if n.is_static {
            "_class: sys::jclass"
        } else {
            "this: sys::jobject"
        });
        for (i, p) in n.params.iter().enumerate() {
            let _ = write!(params, ", a{i}: {}", raw_ty(p));
        }
        let rret = raw_ret(&n.ret);
        let ret_ty = rust_ty(&n.ret);
        let mut conv = String::new();
        if !n.is_static {
            conv.push_str("let this = unsafe { JObject::from_raw(this) }; ");
        }
        for (i, p) in n.params.iter().enumerate() {
            conv.push_str(&convert_arg(p, &format!("a{i}")));
            conv.push(' ');
        }
        let args: Vec<String> = (!n.is_static)
            .then(|| "&this".to_string())
            .into_iter()
            .chain((0..n.params.len()).map(|i| format!("a{i}")))
            .collect();
        let body = if let Some(b) = runtime_body(n) {
            n_rt += 1;
            b.to_string()
        } else if let Some(path) = impls.get(&(n.class.clone(), n.method.clone())) {
            n_impl += 1;
            format!("crate::impls::{path}(env, {})", args.join(", "))
        } else if let Some(b) = structs
            .contains(n.class.as_str())
            .then(|| struct_body(n))
            .flatten()
        {
            n_struct += 1;
            b
        } else if is_rpn(n) {
            n_rpn += 1;
            if n.throws {
                format!("rt::rpn_unsupported(\"{what}\")")
            } else {
                "rt::zero_value()".into()
            }
        } else {
            n_stub += 1;
            if list_stubs {
                eprintln!("stub\t{}\t{}", n.class, n.method);
            }
            if n.throws {
                format!("rt::unimplemented(\"{what}\")")
            } else {
                "rt::zero_value()".into()
            }
        };
        let _ = writeln!(o, "#[unsafe(no_mangle)]");
        let _ = writeln!(
            o,
            "pub extern \"system\" fn {}<'l>({params}) -> {rret} {{",
            sym(n)
        );
        let _ = writeln!(
            o,
            "    unsafe {{ rt::enter::<'l, {ret_ty}, _>(env, \"{what}\", {}, |env| {{ {conv}{body} }}) }}",
            n.throws
        );
        o.push_str("}\n");
    }
    let _ = writeln!(
        o,
        "\n/// Natives with a real implementation (impls + struct accessors + runtime).\npub const fn implemented_count() -> usize {{ {} }}",
        n_impl + n_struct + n_rt
    );
    let _ = writeln!(
        o,
        "pub const STUB_CENSUS: (usize, usize) = ({n_stub}, {n_rpn}); // (unimplemented, rpn)"
    );

    if symbols {
        for n in &natives {
            println!("{}", sym(n));
        }
        return;
    }
    let out = engine.join("crates/fs-jni/src/exports.rs");
    if check {
        let cur = fs::read_to_string(&out).unwrap_or_default();
        if cur != o {
            eprintln!("exports.rs is stale: run `cargo run -p jni-gen` in engine/");
            process::exit(1);
        }
    } else {
        fs::write(&out, &o).expect("write exports.rs");
    }
    eprintln!(
        "jni-gen: {} natives @ firestack {pin}: impl {n_impl}, struct {n_struct}, runtime {n_rt}, rpn-stub {n_rpn}, unimplemented {n_stub}",
        natives.len()
    );
}

fn simple_outer(class: &str) -> String {
    class.rsplit('.').next().unwrap().replace("$proxy", ".")
}
