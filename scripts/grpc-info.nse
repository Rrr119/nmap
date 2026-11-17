local grpc = require "grpc"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates services exposed by a gRPC server through the gRPC Server
Reflection protocol and prints their protobuf service and message
descriptions.

The script supports both cleartext HTTP/2 (h2c) and HTTP/2 over TLS. It first
tries the versioned reflection service (<code>grpc.reflection.v1</code>) and
falls back to the older <code>grpc.reflection.v1alpha</code> service when
needed. For every advertised service, the script requests the protobuf
<code>FileDescriptorProto</code> containing that service, decodes it, and
renders the result as <code>.proto</code> source.

The target must have server reflection enabled. This is enabled by default in
many development servers, but is often disabled in production.

References:
* https://github.com/grpc/grpc/blob/master/doc/server-reflection.md
* https://www.rfc-editor.org/rfc/rfc7540
* https://www.rfc-editor.org/rfc/rfc7541
]]

---
-- @usage
-- nmap -p 50051 --script grpc-info <target>
-- @usage
-- nmap -p 443 --script grpc-info --script-args grpc-info.scheme=https <target>
--
-- @args grpc-info.timeout Socket timeout in milliseconds. Default: 5000.
-- @args grpc-info.scheme Force <code>http</code> (h2c) or <code>https</code>.
--                         By default both are tried unless the port is known
--                         to use TLS.
-- @args grpc-info.host Value for the reflection request's <code>host</code>
--                      field and the HTTP/2 <code>:authority</code> pseudo
--                      header. Defaults to the Nmap target name.
--
-- @output
-- 50051/tcp open  unknown
-- | grpc-info:
-- |   reflection service: grpc.reflection.v1.ServerReflection
-- |   transport: http
-- |   services:
-- |     helloworld.Greeter
-- |   methods:
-- |     helloworld.Greeter
-- |       SayHello(helloworld.HelloRequest) returns (helloworld.HelloReply)
-- |   proto:
-- |     // helloworld.proto
-- |     syntax = "proto3";
-- |     package helloworld;
-- |
-- |     message HelloRequest {
-- |       string name = 1;
-- |     }
-- |
-- |     message HelloReply {
-- |       string message = 1;
-- |     }
-- |
-- |     service Greeter {
-- |       rpc SayHello (helloworld.HelloRequest) returns (helloworld.HelloReply);
-- |     }
-- |_    ...

author = "Nmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
    or 5000
  local scheme = stdnse.get_script_args(SCRIPT_NAME .. ".scheme")
  local request_host = stdnse.get_script_args(SCRIPT_NAME .. ".host")
  if scheme and scheme ~= "http" and scheme ~= "https" then
    return "grpc-info.scheme must be http or https"
  end

  local result, err = grpc.discover(host, port, {
    timeout = timeout,
    scheme = scheme,
    host = request_host,
  })
  if not result then
    stdnse.debug1("gRPC reflection failed: %s", err)
    return nil
  end
  if #result.services == 0 then
    return ("gRPC reflection is available via %s, but no services are registered.")
      :format(result.reflection_service)
  end

  local output = stdnse.output_table()
  output["reflection service"] = result.reflection_service
  output["transport"] = result.scheme
  output["services"] = result.services
  output["methods"] = result.summaries
  output["proto"] = {}
  for _, file in ipairs(result.files) do
    output["proto"][#output["proto"] + 1] = (("// %s\n%s"):format(
      file.name or "<unnamed>", file.proto):gsub("\n", "\n    "))
  end
  if #result.errors > 0 then
    output["descriptor errors"] = result.errors
  end
  return output
end
