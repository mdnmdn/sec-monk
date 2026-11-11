# Store golden data

`save_inventory.json`: inventories as stored and the rows `engine/inventory.save_inventory` (Python, schema v2)
writes for them, timestamps replaced by `"TS"`. Sample: synthetic plus the contract example
`rust/contracts/examples/inventory/fs-npm-v3.json`. Generated on 2026-11-11 by `gen_save_inventory.py`
(command in its docstring). `tests/store.rs` checks the Rust store writes the same v2 columns.
