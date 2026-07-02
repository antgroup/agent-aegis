/**
 * JSON-RPC stdio server for AgentAegis.
 *
 * Protocol: line-delimited JSON on stdin/stdout.
 *   Request:  {"id":1, "method":"check_before_tool", "params":{...}}
 *   Response: {"id":1, "result":{...}}
 *   Error:    {"id":1, "error":{"message":"...", "code":-32000}}
 *
 * All diagnostic logging goes to stderr so it never corrupts the protocol.
 *
 * Usage:
 *   node rpc-server.js              # interactive stdio mode
 *   echo '{"id":1,...}' | node rpc-server.js   # single-shot pipe mode
 */
export {};
