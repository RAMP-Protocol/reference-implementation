// Proto module. Published from this repo via a replace directive in the
// parent go.mod; will be extracted to its own public repository later
// without any changes required in dependent services.
module github.com/postindustria-tech/ramp-protocol

go 1.26

require (
	connectrpc.com/connect v1.19.1
	google.golang.org/protobuf v1.36.11
)
