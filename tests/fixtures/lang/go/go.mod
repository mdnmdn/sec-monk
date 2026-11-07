module example.com/secmonk-hello

go 1.21

require (
	example.com/localfork v0.0.0
	github.com/google/uuid v1.3.0
	golang.org/x/text v0.3.7
)

replace example.com/localfork => ../localfork

replace github.com/google/uuid v1.3.0 => github.com/google/uuid v1.3.1
