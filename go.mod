module github.com/michaellady/verified-java-websocket-port

go 1.25

require github.com/michaellady/verified-java-to-rust/foundation v0.0.0

require (
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/michaellady/verified-java-to-rust/foundation => ./third_party/verified-java-to-rust-foundation
