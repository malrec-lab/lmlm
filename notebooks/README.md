# Notebooks

Notebooks support exploration, review, and figures. Name them `<order>-<initials>-<topic>.ipynb` so their intended reading order is clear. Keep inputs and outputs parameterized, avoid embedding credentials or sample contents, and promote reusable logic into the `malweave` package with tests.

## Walkthroughs

- `01-malweave-reproduction-preprocessing.ipynb` runs the implemented paper flow end to end: filter PE32 x86 samples, reject obfuscated binaries, and materialize the EXE, DIS, and DEC representations.
- `02-malweave-tokenization.ipynb` trains independent BPE tokenizers and materializes EXE, DIS, and DEC token sequences, with previews of inputs, learned vocabulary, token IDs, and sequence statistics.
