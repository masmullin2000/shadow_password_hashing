#![allow(unused_imports)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use lib::*;

//const WORDLIST: &str = "/usr/share/wordlists/seclists/Passwords/darkweb2017-top10000.txt";
const WORDLIST: &str = "wordlist";

fn run_test(name: &str, c: &mut Criterion) {
    let mut g = c.benchmark_group(name);
    g.sample_size(10);
    g.bench_function("bench", |b| b.iter(|| crack_shadow("shadow", WORDLIST)) ); 
    g.finish();
}

fn bench(c: &mut Criterion) {
    run_test("crack_shadow", c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
