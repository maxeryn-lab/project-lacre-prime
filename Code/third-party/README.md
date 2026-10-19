# Code/third-party — algoritmo de un tercero (E6)

Workspace de Cargo APARTE del de producción. Demuestra que un tercero añade un algoritmo de sello sin tocar el Núcleo:

- `hmac-sha3-256-seal/`: el algoritmo (implementa `SealMac`; solo depende de `lacre-core`, `hmac` y `sha3`). Pasa `check_seal_mac` con vectores de Python (`tests/vectors.json`, generados por `Tools/gen_third_party_vectors.py`).
- `node-with-hmac-sha3-256/`: el mismo nodo que `lacre-server` con el algoritmo añadido al registro, en compilación.
- `CORE-HASH-BEFORE.txt`: huella de los 36 archivos de `lacre-core/` y del `Cargo.toml` de producción antes de añadirlo. `python3 Tools/core_hash.py --compare Code/third-party/CORE-HASH-BEFORE.txt` debe decir IDÉNTICO.
- Recorrido completo contra el nodo real: `python3 Tools/e6_third_party_e2e.py --node Code/third-party/target/debug/node-with-hmac-sha3-256 --stock Code/workspace/target/debug/lacre-server`.

El algoritmo se declara `experimental`: la palabra `standard` la da el catálogo de Lacre, no un tercero. Compilado no es autorizado: la política del operador debe nombrarlo.
