use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nullwarden_core::crypto::{encrypt, decrypt};

fn bench_crypto(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = vec![0u8; 1024]; // 1KB
    
    c.bench_function("encrypt_1kb", |b| {
        b.iter(|| {
            encrypt(&key, black_box(&data)).unwrap()
        })
    });

    let (nonce, ciphertext) = encrypt(&key, &data).unwrap();
    c.bench_function("decrypt_1kb", |b| {
        b.iter(|| {
            decrypt(&key, &nonce, black_box(&ciphertext)).unwrap()
        })
    });
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
