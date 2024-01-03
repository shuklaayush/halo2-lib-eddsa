# halo2-lib-eddsa

https://shuklaayu.sh/blog/axiom-ed25519


Currently to use this crate in your repo you will have to add the following to `.cargo/config.toml`:
```toml
[patch.crates-io]
halo2curves_axiom = { git = "https://github.com/axiom-crypto/halo2curves.git", branch = "feat/ed25519", package = "halo2curves-axiom" }

[patch."https://github.com/axiom-crypto/halo2-lib.git"]
halo2_base = { git = "https://github.com//axiom-crypto/halo2-lib.git", branch = "feat/ed25519", package = "halo2_base" }
halo2_ecc = { git = "https://github.com//axiom-crypto/halo2-lib.git", branch = "feat/ed25519", package = "halo2_ecc" }
```
