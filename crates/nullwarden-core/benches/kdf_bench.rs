use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nullwarden_core::kdf::{derive_key, generate_salt, KdfParams};
use std::time::Duration;

fn bench_argon2id(c: &mut Criterion) {
    let salt = generate_salt();
    let params = KdfParams::default();

    // NFR-P1: KDF latency gate (Argon2 params must produce >= 300ms latency)
    let start = std::time::Instant::now();
    derive_key(b"password", &salt, params).unwrap();
    let elapsed = start.elapsed();
    if elapsed < Duration::from_millis(300) {
        panic!(
            "KDF too fast: {:?}. Argon2 params must produce >= 300ms latency.",
            elapsed
        );
    }

    c.bench_function("argon2id_derive_key", |b| {
        b.iter(|| derive_key(black_box(b"test_master_password"), &salt, params).unwrap())
    });
}

criterion_group!(benches, bench_argon2id);
criterion_main!(benches);
