# secmonk-runtime fixtures

`audit-project/`: a synthetic uv project (one empty package, `uv_build` backend) used by the ignored `uv_audit`
test. The test copies it to a temp directory and locks it there with the pinned uv; nothing is generated in the
repo. Sample: synthetic.
