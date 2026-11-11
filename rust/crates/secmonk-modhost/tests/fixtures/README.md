# secmonk-modhost fixtures

`echo_module.py`: a tiny `secmonk-wire/1` module (stdlib only, Python >= 3.9) used by `tests/modhost.rs` as a
stand-in for the real modules of `rust/python` (W2.2). Sample: synthetic. The tests run it with `python3 -I`
from `PATH` and skip when no `python3` is found.
