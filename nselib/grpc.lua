--- Minimal gRPC and HTTP/2 support for NSE.
--
-- This library implements enough of HTTP/2 (RFC 7540), HPACK (RFC 7541),
-- gRPC framing, and the gRPC server reflection protocol to enumerate services
-- and retrieve their protobuf file descriptors. It is intentionally
-- self-contained because NSE does not currently provide an HTTP/2 client.
--
-- @author "Nmap"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

local have_zlib, zlib = pcall(require, "zlib")

_ENV = stdnse.module("grpc", stdnse.seeall)

local DEFAULT_TIMEOUT = 5000
local MAX_FRAME_SIZE = 16 * 1024 * 1024
local MAX_MESSAGE_SIZE = 8 * 1024 * 1024
local MAX_RESPONSE_SIZE = 32 * 1024 * 1024
local MAX_STREAMS = 1000

local FRAME = {
  DATA = 0x0,
  HEADERS = 0x1,
  PRIORITY = 0x2,
  RST_STREAM = 0x3,
  SETTINGS = 0x4,
  PUSH_PROMISE = 0x5,
  PING = 0x6,
  GOAWAY = 0x7,
  WINDOW_UPDATE = 0x8,
  CONTINUATION = 0x9,
}

local FLAG = {
  END_STREAM = 0x1,
  ACK = 0x1,
  END_HEADERS = 0x4,
  PADDED = 0x8,
  PRIORITY = 0x20,
}

local SETTINGS = {
  HEADER_TABLE_SIZE = 0x1,
  ENABLE_PUSH = 0x2,
  MAX_CONCURRENT_STREAMS = 0x3,
  INITIAL_WINDOW_SIZE = 0x4,
  MAX_FRAME_SIZE = 0x5,
  MAX_HEADER_LIST_SIZE = 0x6,
}

local HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
local CLIENT_WINDOW = 1024 * 1024
local CONNECTION_WINDOW = 16 * 1024 * 1024

local REFLECTION_SERVICES = {
  "grpc.reflection.v1.ServerReflection",
  "grpc.reflection.v1alpha.ServerReflection",
}

local function u24(value)
  return string.char(
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff
  )
end

local function pack_frame(frame_type, flags, stream_id, payload)
  payload = payload or ""
  if #payload > MAX_FRAME_SIZE then
    error("HTTP/2 frame too large")
  end
  return u24(#payload)
    .. string.char(frame_type, flags)
    .. string.pack(">I4", stream_id & 0x7fffffff)
    .. payload
end

local function unpack_frame_header(header)
  if #header < 9 then
    return nil, "short HTTP/2 frame header"
  end
  local b1, b2, b3, frame_type, flags,
    s1, s2, s3, s4 = string.byte(header, 1, 9)
  local length = (b1 << 16) | (b2 << 8) | b3
  local stream_id = ((s1 & 0x7f) << 24) | (s2 << 16) | (s3 << 8) | s4
  return {
    length = length,
    type = frame_type,
    flags = flags,
    stream_id = stream_id,
  }
end

local function grpc_frame(message)
  return string.char(0) .. string.pack(">I4", #message) .. message
end

local function parse_grpc_frames(data, encoding)
  local messages = {}
  local pos = 1
  while pos <= #data do
    if pos + 4 > #data then
      return nil, "truncated gRPC message header"
    end
    local compressed = string.byte(data, pos)
    local length = string.unpack(">I4", data, pos + 1)
    pos = pos + 5
    if length > MAX_MESSAGE_SIZE then
      return nil, ("gRPC message too large: %d bytes"):format(length)
    end
    if pos + length - 1 > #data then
      return nil, "truncated gRPC message body"
    end
    local body = string.sub(data, pos, pos + length - 1)
    pos = pos + length
    if compressed ~= 0 then
      if encoding == "gzip" and have_zlib then
        local ok, result, zerr = pcall(zlib.decompress, body, 31,
          MAX_MESSAGE_SIZE)
        if not ok or not result then
          return nil, "failed to decompress gRPC message: "
            .. tostring(ok and zerr or result)
        end
        body = result
      else
        return nil, ("unsupported compressed gRPC message (encoding=%s)"):format(
          encoding or "unknown")
      end
    end
    messages[#messages + 1] = body
  end
  return messages
end

local function encode_varint(value)
  if value < 0 then
    value = value + 0x10000000000000000
  end
  local out = {}
  repeat
    local byte = value & 0x7f
    value = value >> 7
    if value ~= 0 then
      byte = byte | 0x80
    end
    out[#out + 1] = string.char(byte)
  until value == 0
  return table.concat(out)
end

local function decode_varint(data, pos)
  local value = 0
  local shift = 0
  while true do
    if pos > #data then
      return nil, nil, "truncated varint"
    end
    local byte = string.byte(data, pos)
    pos = pos + 1
    value = value | ((byte & 0x7f) << shift)
    if byte < 0x80 then
      break
    end
    shift = shift + 7
    if shift >= 70 then
      return nil, nil, "varint too long"
    end
  end
  if value >= 0x8000000000000000 then
    value = value - 0x10000000000000000
  end
  return value, pos
end

local function encode_pb_varint(field, value)
  return encode_varint((field << 3) | 0) .. encode_varint(value)
end

local function encode_pb_bytes(field, value)
  value = value or ""
  return encode_varint((field << 3) | 2) .. encode_varint(#value) .. value
end

local function parse_pb(data)
  local fields = {}
  local pos = 1
  while pos <= #data do
    local key
    key, pos = decode_varint(data, pos)
    if not key then
      return nil, "invalid protobuf field key"
    end
    local field = key >> 3
    local wire = key & 7
    local value
    if field == 0 then
      return nil, "invalid protobuf field number 0"
    elseif wire == 0 then
      value, pos = decode_varint(data, pos)
    elseif wire == 1 then
      if pos + 7 > #data then
        return nil, "truncated fixed64 field"
      end
      value = string.unpack(">I8", data, pos)
      pos = pos + 8
    elseif wire == 2 then
      local length
      length, pos = decode_varint(data, pos)
      if not length or length < 0 or pos + length - 1 > #data then
        return nil, "truncated length-delimited field"
      end
      value = string.sub(data, pos, pos + length - 1)
      pos = pos + length
    elseif wire == 5 then
      if pos + 3 > #data then
        return nil, "truncated fixed32 field"
      end
      value = string.unpack(">I4", data, pos)
      pos = pos + 4
    else
      return nil, ("unsupported protobuf wire type %d"):format(wire)
    end
    if value == nil then
      return nil, "truncated protobuf value"
    end
    fields[#fields + 1] = {
      field = field,
      wire = wire,
      value = value,
    }
  end
  return fields
end

local function pb_values(fields, number)
  local values = {}
  for _, item in ipairs(fields) do
    if item.field == number then
      values[#values + 1] = item.value
    end
  end
  return values
end

local function pb_value(fields, number)
  local values = pb_values(fields, number)
  return values[1]
end

local function pb_message(data)
  local fields, err = parse_pb(data)
  if not fields then
    return nil, err
  end
  return fields
end

-- RFC 7541 Appendix A
local HPACK_STATIC = {
  false,
  { ":authority", "" },
  { ":method", "GET" },
  { ":method", "POST" },
  { ":path", "/" },
  { ":path", "/index.html" },
  { ":scheme", "http" },
  { ":scheme", "https" },
  { ":status", "200" },
  { ":status", "204" },
  { ":status", "206" },
  { ":status", "304" },
  { ":status", "400" },
  { ":status", "404" },
  { ":status", "500" },
  { "accept-charset", "" },
  { "accept-encoding", "gzip, deflate" },
  { "accept-language", "" },
  { "accept-ranges", "" },
  { "accept", "" },
  { "access-control-allow-origin", "" },
  { "age", "" },
  { "allow", "" },
  { "authorization", "" },
  { "cache-control", "" },
  { "content-disposition", "" },
  { "content-encoding", "" },
  { "content-language", "" },
  { "content-length", "" },
  { "content-location", "" },
  { "content-range", "" },
  { "content-type", "" },
  { "cookie", "" },
  { "date", "" },
  { "etag", "" },
  { "expect", "" },
  { "expires", "" },
  { "from", "" },
  { "host", "" },
  { "if-match", "" },
  { "if-modified-since", "" },
  { "if-none-match", "" },
  { "if-range", "" },
  { "if-unmodified-since", "" },
  { "last-modified", "" },
  { "link", "" },
  { "location", "" },
  { "max-forwards", "" },
  { "proxy-authenticate", "" },
  { "proxy-authorization", "" },
  { "range", "" },
  { "referer", "" },
  { "refresh", "" },
  { "retry-after", "" },
  { "server", "" },
  { "set-cookie", "" },
  { "strict-transport-security", "" },
  { "transfer-encoding", "" },
  { "user-agent", "" },
  { "vary", "" },
  { "via", "" },
  { "www-authenticate", "" },
}

-- RFC 7541 Appendix B. The final entry is the EOS symbol.
local HUFFMAN_CODES = {
  8184, 8388568, 268435426, 268435427, 268435428, 268435429, 268435430, 268435431,
  268435432, 16777194, 1073741820, 268435433, 268435434, 1073741821, 268435435, 268435436,
  268435437, 268435438, 268435439, 268435440, 268435441, 268435442, 1073741822, 268435443,
  268435444, 268435445, 268435446, 268435447, 268435448, 268435449, 268435450, 268435451,
  20, 1016, 1017, 4090, 8185, 21, 248, 2042,
  1018, 1019, 249, 2043, 250, 22, 23, 24,
  0, 1, 2, 25, 26, 27, 28, 29,
  30, 31, 92, 251, 32764, 32, 4091, 1020,
  8186, 33, 93, 94, 95, 96, 97, 98,
  99, 100, 101, 102, 103, 104, 105, 106,
  107, 108, 109, 110, 111, 112, 113, 114,
  252, 115, 253, 8187, 524272, 8188, 16380, 34,
  32765, 3, 35, 4, 36, 5, 37, 38,
  39, 6, 116, 117, 40, 41, 42, 7,
  43, 118, 44, 8, 9, 45, 119, 120,
  121, 122, 123, 32766, 2044, 16381, 8189, 268435452,
  1048550, 4194258, 1048551, 1048552, 4194259, 4194260, 4194261, 8388569,
  4194262, 8388570, 8388571, 8388572, 8388573, 8388574, 16777195, 8388575,
  16777196, 16777197, 4194263, 8388576, 16777198, 8388577, 8388578, 8388579,
  8388580, 2097116, 4194264, 8388581, 4194265, 8388582, 8388583, 16777199,
  4194266, 2097117, 1048553, 4194267, 4194268, 8388584, 8388585, 2097118,
  8388586, 4194269, 4194270, 16777200, 2097119, 4194271, 8388587, 8388588,
  2097120, 2097121, 4194272, 2097122, 8388589, 4194273, 8388590, 8388591,
  1048554, 4194274, 4194275, 4194276, 8388592, 4194277, 4194278, 8388593,
  67108832, 67108833, 1048555, 524273, 4194279, 8388594, 4194280, 33554412,
  67108834, 67108835, 67108836, 134217694, 134217695, 67108837, 16777201, 33554413,
  524274, 2097123, 67108838, 134217696, 134217697, 67108839, 134217698, 16777202,
  2097124, 2097125, 67108840, 67108841, 268435453, 134217699, 134217700, 134217701,
  1048556, 16777203, 1048557, 2097126, 4194281, 2097127, 2097128, 8388595,
  4194282, 4194283, 33554414, 33554415, 16777204, 16777205, 67108842, 8388596,
  67108843, 134217702, 67108844, 67108845, 134217703, 134217704, 134217705, 134217706,
  134217707, 268435454, 134217708, 134217709, 134217710, 134217711, 134217712, 67108846,
  1073741823,
}

local HUFFMAN_LENGTHS = {
  13, 23, 28, 28, 28, 28, 28, 28,
  28, 24, 30, 28, 28, 30, 28, 28,
  28, 28, 28, 28, 28, 28, 30, 28,
  28, 28, 28, 28, 28, 28, 28, 28,
  6, 10, 10, 12, 13, 6, 8, 11,
  10, 10, 8, 11, 8, 6, 6, 6,
  5, 5, 5, 6, 6, 6, 6, 6,
  6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7,
  8, 7, 8, 13, 19, 13, 14, 6,
  15, 5, 6, 5, 6, 5, 6, 6,
  6, 5, 7, 7, 6, 6, 6, 5,
  6, 7, 6, 5, 5, 6, 7, 7,
  7, 7, 7, 15, 11, 14, 13, 28,
  20, 22, 20, 20, 22, 22, 22, 23,
  22, 23, 23, 23, 23, 23, 24, 23,
  24, 24, 22, 23, 24, 23, 23, 23,
  23, 21, 22, 23, 22, 23, 23, 24,
  22, 21, 20, 22, 22, 23, 23, 21,
  23, 22, 22, 24, 21, 22, 23, 23,
  21, 21, 22, 21, 23, 22, 23, 23,
  20, 22, 22, 22, 23, 22, 22, 23,
  26, 26, 20, 19, 22, 23, 22, 25,
  26, 26, 26, 27, 27, 26, 24, 25,
  19, 21, 26, 27, 27, 26, 27, 24,
  21, 21, 26, 26, 28, 27, 27, 27,
  20, 24, 20, 21, 22, 21, 21, 23,
  22, 22, 25, 25, 24, 24, 26, 23,
  26, 27, 26, 26, 27, 27, 27, 27,
  27, 28, 27, 27, 27, 27, 27, 26,
  30,
}

local function build_huffman_tree()
  local root = {}
  for symbol = 0, 256 do
    local code = HUFFMAN_CODES[symbol + 1]
    local length = HUFFMAN_LENGTHS[symbol + 1]
    local node = root
    for bitpos = length - 1, 0, -1 do
      local bit = (code >> bitpos) & 1
      node[bit] = node[bit] or {}
      node = node[bit]
    end
    node.symbol = symbol
  end
  return root
end

local HUFFMAN_TREE = build_huffman_tree()

local function huffman_decode(data)
  local out = {}
  local node = HUFFMAN_TREE
  local pending = 0
  local pending_value = 0
  for i = 1, #data do
    local byte = string.byte(data, i)
    for bitpos = 7, 0, -1 do
      local bit = (byte >> bitpos) & 1
      node = node[bit]
      if not node then
        return nil, "invalid HPACK Huffman code"
      end
      pending = pending + 1
      pending_value = (pending_value << 1) | bit
      if node.symbol then
        if node.symbol == 256 then
          return nil, "unexpected HPACK Huffman EOS symbol"
        end
        out[#out + 1] = string.char(node.symbol)
        node = HUFFMAN_TREE
        pending = 0
        pending_value = 0
      end
    end
  end
  if node ~= HUFFMAN_TREE then
    if pending > 7 or pending_value ~= (1 << pending) - 1 then
      return nil, "invalid HPACK Huffman padding"
    end
  end
  return table.concat(out)
end

local function hpack_decode_integer(data, pos, prefix_bits)
  if pos > #data then
    return nil, nil, "truncated HPACK integer"
  end
  local mask = (1 << prefix_bits) - 1
  local byte = string.byte(data, pos)
  pos = pos + 1
  local value = byte & mask
  if value < mask then
    return value, pos
  end
  local shift = 0
  while true do
    if pos > #data then
      return nil, nil, "truncated HPACK integer"
    end
    byte = string.byte(data, pos)
    pos = pos + 1
    value = value + ((byte & 0x7f) << shift)
    if byte < 0x80 then
      return value, pos
    end
    shift = shift + 7
    if shift > 56 then
      return nil, nil, "HPACK integer too large"
    end
  end
end

local function hpack_encode_integer(value, prefix_bits, first_bits)
  local limit = (1 << prefix_bits) - 1
  local out = {}
  if value < limit then
    return string.char(first_bits | value)
  end
  out[#out + 1] = string.char(first_bits | limit)
  value = value - limit
  repeat
    local byte = value & 0x7f
    value = value >> 7
    if value ~= 0 then
      byte = byte | 0x80
    end
    out[#out + 1] = string.char(byte)
  until value == 0
  return table.concat(out)
end

local function hpack_decode_string(data, pos)
  if pos > #data then
    return nil, nil, "truncated HPACK string"
  end
  local huffman = (string.byte(data, pos) & 0x80) ~= 0
  local length, newpos, err = hpack_decode_integer(data, pos, 7)
  if not length then
    return nil, nil, err
  end
  pos = newpos
  if pos + length - 1 > #data then
    return nil, nil, "truncated HPACK string"
  end
  local value = string.sub(data, pos, pos + length - 1)
  pos = pos + length
  if huffman then
    value, err = huffman_decode(value)
    if not value then
      return nil, nil, err
    end
  end
  return value, pos
end

local function hpack_encode_string(value)
  return hpack_encode_integer(#value, 7, 0) .. value
end

local HPACK = {}

function HPACK:new(max_size)
  local o = {
    dynamic = {},
    size = 0,
    max_size = max_size or 4096,
  }
  return setmetatable(o, { __index = self })
end

function HPACK:get(index)
  if index <= 0 then
    return nil
  end
  if index <= #HPACK_STATIC - 1 then
    local entry = HPACK_STATIC[index + 1]
    return entry[1], entry[2]
  end
  local entry = self.dynamic[index - (#HPACK_STATIC - 1)]
  if entry then
    return entry[1], entry[2]
  end
end

function HPACK:add(name, value)
  local entry = { name, value }
  local size = #name + #value + 32
  if size > self.max_size then
    self.dynamic = {}
    self.size = 0
    return
  end
  table.insert(self.dynamic, 1, entry)
  self.size = self.size + size
  while self.size > self.max_size do
    local removed = table.remove(self.dynamic)
    self.size = self.size - (#removed[1] + #removed[2] + 32)
  end
end

function HPACK:set_max_size(max_size)
  self.max_size = max_size
  while self.size > self.max_size do
    local removed = table.remove(self.dynamic)
    self.size = self.size - (#removed[1] + #removed[2] + 32)
  end
end

function HPACK:decode(data)
  local headers = {}
  local pos = 1
  while pos <= #data do
    local byte = string.byte(data, pos)
    local name, value, index, err
    if (byte & 0x80) ~= 0 then
      index, pos = hpack_decode_integer(data, pos, 7)
      if not index then
        return nil, pos
      end
      name, value = self:get(index)
      if not name then
        return nil, ("invalid HPACK static/dynamic index %d"):format(index)
      end
    elseif (byte & 0xe0) == 0x20 then
      index, pos = hpack_decode_integer(data, pos, 5)
      if not index then
        return nil, pos
      end
      self:set_max_size(index)
      goto continue
    elseif (byte & 0xc0) == 0x40 then
      index, pos = hpack_decode_integer(data, pos, 6)
      if index == 0 then
        name, pos = hpack_decode_string(data, pos)
        if not name then
          return nil, pos
        end
      else
        name = self:get(index)
        if not name then
          return nil, ("invalid HPACK name index %d"):format(index)
        end
      end
      value, pos = hpack_decode_string(data, pos)
      if not value then
        return nil, pos
      end
      self:add(name, value)
    else
      index, pos = hpack_decode_integer(data, pos, 4)
      if not index then
        return nil, pos
      end
      if index == 0 then
        name, pos = hpack_decode_string(data, pos)
        if not name then
          return nil, pos
        end
      else
        name = self:get(index)
        if not name then
          return nil, ("invalid HPACK name index %d"):format(index)
        end
      end
      value, pos = hpack_decode_string(data, pos)
      if not value then
        return nil, pos
      end
    end
    headers[#headers + 1] = {
      name = string.lower(name),
      value = value,
    }
    ::continue::
  end
  return headers
end

function HPACK:encode(headers)
  local out = {}
  for _, header in ipairs(headers) do
    out[#out + 1] = hpack_encode_integer(0, 4, 0)
      .. hpack_encode_string(header.name)
      .. hpack_encode_string(header.value)
  end
  return table.concat(out)
end

local HTTP2 = {}

function HTTP2:new(socket, options)
  local o = {
    socket = socket,
    buffer = "",
    hpack = HPACK:new(4096),
    next_stream_id = 1,
    streams = {},
    closed = false,
    max_concurrent = options and options.max_concurrent or 1,
  }
  return setmetatable(o, { __index = self })
end

function HTTP2:send_frame(frame_type, flags, stream_id, payload)
  local status, err = self.socket:send(pack_frame(
    frame_type, flags, stream_id, payload))
  if not status then
    return nil, err
  end
  return true
end

function HTTP2:read_exact(length)
  while #self.buffer < length do
    local status, data = self.socket:receive()
    if not status then
      return nil, data
    end
    if not data or #data == 0 then
      return nil, "connection closed"
    end
    self.buffer = self.buffer .. data
  end
  local result = string.sub(self.buffer, 1, length)
  self.buffer = string.sub(self.buffer, length + 1)
  return result
end

function HTTP2:read_frame()
  local header, err = self:read_exact(9)
  if not header then
    return nil, err
  end
  local frame, ferr = unpack_frame_header(header)
  if not frame then
    return nil, ferr
  end
  if frame.length > MAX_FRAME_SIZE then
    return nil, ("HTTP/2 frame too large: %d bytes"):format(frame.length)
  end
  frame.payload, err = self:read_exact(frame.length)
  if not frame.payload then
    return nil, err
  end
  stdnse.debug3("HTTP/2 frame type=%d flags=0x%02x stream=%d length=%d",
    frame.type, frame.flags, frame.stream_id, frame.length)
  return frame
end

function HTTP2:send_settings()
  local settings = string.pack(">HI4", SETTINGS.ENABLE_PUSH, 0)
    .. string.pack(">HI4", SETTINGS.INITIAL_WINDOW_SIZE, CLIENT_WINDOW)
    .. string.pack(">HI4", SETTINGS.MAX_FRAME_SIZE, 16384)
  local status, err = self:send_frame(FRAME.SETTINGS, 0, 0, settings)
  if not status then
    return nil, err
  end
  return self:send_frame(FRAME.WINDOW_UPDATE, 0, 0,
    string.pack(">I4", CONNECTION_WINDOW - 65535))
end

function HTTP2:handshake()
  local status, err = self.socket:send(HTTP2_PREFACE)
  if not status then
    return nil, err
  end
  return self:send_settings()
end

local function strip_padding(payload, flags)
  if (flags & FLAG.PADDED) == 0 then
    return payload
  end
  if #payload < 1 then
    return nil, "truncated padded frame"
  end
  local pad_length = string.byte(payload, 1)
  if pad_length + 1 > #payload then
    return nil, "invalid HTTP/2 frame padding"
  end
  return string.sub(payload, 2, #payload - pad_length)
end

local function header_fragment(frame)
  local payload = strip_padding(frame.payload, frame.flags)
  if not payload then
    return nil, "invalid HEADERS padding"
  end
  if (frame.flags & FLAG.PRIORITY) ~= 0 then
    if #payload < 5 then
      return nil, "truncated HEADERS priority"
    end
    payload = string.sub(payload, 6)
  end
  return payload
end

function HTTP2:read_header_block(frame)
  if frame.type ~= FRAME.HEADERS or frame.stream_id == 0 then
    return nil, "expected HEADERS frame"
  end
  local parts = {}
  local fragment, err = header_fragment(frame)
  if not fragment then
    return nil, err
  end
  parts[#parts + 1] = fragment
  while (frame.flags & FLAG.END_HEADERS) == 0 do
    frame, err = self:read_frame()
    if not frame then
      return nil, err
    end
    if frame.type ~= FRAME.CONTINUATION
      or frame.stream_id ~= self.last_header_stream then
      return nil, "invalid HTTP/2 header continuation"
    end
    parts[#parts + 1] = frame.payload
  end
  return table.concat(parts)
end

function HTTP2:handle_control(frame)
  if frame.type == FRAME.SETTINGS then
    if frame.stream_id ~= 0 then
      return nil, "SETTINGS frame on a stream"
    end
    if (frame.flags & FLAG.ACK) == 0 then
      return self:send_frame(FRAME.SETTINGS, FLAG.ACK, 0, "")
    end
    return true
  elseif frame.type == FRAME.PING then
    if frame.stream_id ~= 0 or #frame.payload ~= 8 then
      return nil, "invalid PING frame"
    end
    if (frame.flags & FLAG.ACK) == 0 then
      return self:send_frame(FRAME.PING, FLAG.ACK, 0, frame.payload)
    end
    return true
  elseif frame.type == FRAME.WINDOW_UPDATE then
    return true
  elseif frame.type == FRAME.PRIORITY then
    return true
  elseif frame.type == FRAME.GOAWAY then
    local code = "unknown"
    if #frame.payload >= 8 then
      code = string.unpack(">I4", frame.payload, 5)
    end
    self.closed = true
    return nil, ("server sent GOAWAY (error code %s)"):format(code)
  elseif frame.type == FRAME.RST_STREAM then
    local code = "unknown"
    if #frame.payload >= 4 then
      code = string.unpack(">I4", frame.payload, 1)
    end
    if self.streams[frame.stream_id] then
      self.streams[frame.stream_id].error = ("stream reset (error code %s)"):format(code)
      self.streams[frame.stream_id].ended = true
    end
    return true
  elseif frame.type == FRAME.PUSH_PROMISE then
    return nil, "server push is not supported"
  end
  return true
end

function HTTP2:process_headers(stream, frame)
  self.last_header_stream = frame.stream_id
  local block, err = self:read_header_block(frame)
  if not block then
    return nil, err
  end
  local headers, herr = self.hpack:decode(block)
  if not headers then
    return nil, "failed to decode HPACK headers: " .. tostring(herr)
  end
  for _, header in ipairs(headers) do
    stream.headers[header.name] = header.value
  end
  if (frame.flags & FLAG.END_STREAM) ~= 0 then
    stream.ended = true
  end
  return true
end

function HTTP2:read_stream(stream_id)
  local stream = self.streams[stream_id]
  if not stream then
    return nil, "unknown HTTP/2 stream"
  end
  while not stream.ended do
    local frame, err = self:read_frame()
    if not frame then
      return nil, err
    end
    if frame.type == FRAME.DATA and frame.stream_id == stream_id then
      local payload, derr = strip_padding(frame.payload, frame.flags)
      if not payload then
        return nil, derr
      end
      stream.data[#stream.data + 1] = payload
      stream.data_size = stream.data_size + #payload
      if stream.data_size > MAX_RESPONSE_SIZE then
        return nil, "gRPC response too large"
      end
      if #payload > 0 then
        local status
        status, err = self:send_frame(FRAME.WINDOW_UPDATE, 0, stream_id,
          string.pack(">I4", #payload))
        if not status then
          return nil, err
        end
        status, err = self:send_frame(FRAME.WINDOW_UPDATE, 0, 0,
          string.pack(">I4", #payload))
        if not status then
          return nil, err
        end
      end
      if (frame.flags & FLAG.END_STREAM) ~= 0 then
        stream.ended = true
      end
    elseif frame.type == FRAME.HEADERS and frame.stream_id == stream_id then
      local status
      status, err = self:process_headers(stream, frame)
      if not status then
        return nil, err
      end
    elseif frame.type == FRAME.RST_STREAM and frame.stream_id == stream_id then
      local code = "unknown"
      if #frame.payload >= 4 then
        code = string.unpack(">I4", frame.payload, 1)
      end
      return nil, ("stream reset (error code %s)"):format(code)
    else
      local status
      status, err = self:handle_control(frame)
      if not status then
        return nil, err
      end
    end
  end
  if stream.error then
    return nil, stream.error
  end
  stream.body = table.concat(stream.data)
  return stream
end

function HTTP2:request(path, body, options)
  options = options or {}
  if self.closed then
    return nil, "HTTP/2 connection is closed"
  end
  if self.next_stream_id > 2 * MAX_STREAMS - 1 then
    return nil, "too many HTTP/2 streams"
  end
  local stream_id = self.next_stream_id
  self.next_stream_id = self.next_stream_id + 2
  local stream = {
    id = stream_id,
    headers = {},
    data = {},
    data_size = 0,
  }
  self.streams[stream_id] = stream

  local headers = {
    { name = ":method", value = "POST" },
    { name = ":scheme", value = options.scheme or "http" },
    { name = ":path", value = path },
    { name = ":authority", value = options.authority or "" },
    { name = "content-type", value = "application/grpc" },
    { name = "te", value = "trailers" },
    { name = "user-agent", value = "nmap-nse-grpc" },
  }
  if options.timeout then
    headers[#headers + 1] = {
      name = "grpc-timeout",
      value = tostring(math.max(1, math.floor(options.timeout))) .. "m",
    }
  end
  local status, err = self:send_frame(FRAME.HEADERS, FLAG.END_HEADERS,
    stream_id, self.hpack:encode(headers))
  if not status then
    return nil, err
  end
  status, err = self:send_frame(FRAME.DATA, FLAG.END_STREAM, stream_id,
    grpc_frame(body))
  if not status then
    return nil, err
  end
  return self:read_stream(stream_id)
end

local Reflection = {}

function Reflection:new(http2, options)
  local o = {
    http2 = http2,
    authority = options.authority or "",
    host = options.host or "",
    timeout = options.timeout,
    service = nil,
  }
  return setmetatable(o, { __index = self })
end

function Reflection:reflect_request(field, value)
  local request = ""
  if self.host ~= "" then
    request = request .. encode_pb_bytes(1, self.host)
  end
  if field == "list_services" then
    request = request .. encode_pb_bytes(7, "")
  elseif field == "file_containing_symbol" then
    request = request .. encode_pb_bytes(4, value)
  else
    return nil, "unsupported reflection request"
  end
  return request
end

function Reflection:parse_response(message)
  local fields, err = pb_message(message)
  if not fields then
    return nil, "invalid ServerReflectionResponse: " .. err
  end
  local error_data = pb_value(fields, 7)
  if error_data then
    local error_fields = pb_message(error_data)
    local code = error_fields and pb_value(error_fields, 1) or 2
    local text = error_fields and pb_value(error_fields, 2) or "reflection error"
    return nil, ("reflection error %s: %s"):format(tostring(code), text)
  end
  local services = pb_value(fields, 6)
  if services then
    local service_fields = pb_message(services)
    if not service_fields then
      return nil, "invalid ListServiceResponse"
    end
    local names = {}
    for _, item in ipairs(pb_values(service_fields, 1)) do
      local response_fields = pb_message(item)
      local name = response_fields and pb_value(response_fields, 1)
      if name then
        names[#names + 1] = name
      end
    end
    return { services = names }
  end
  local descriptors = pb_value(fields, 4)
  if descriptors then
    local descriptor_fields = pb_message(descriptors)
    if not descriptor_fields then
      return nil, "invalid FileDescriptorResponse"
    end
    return { descriptors = pb_values(descriptor_fields, 1) }
  end
  return nil, "unsupported ServerReflectionResponse"
end

function Reflection:call(field, value)
  local request, err = self:reflect_request(field, value)
  if not request then
    return nil, err
  end
  local stream
  stream, err = self.http2:request(
    "/" .. self.service .. "/ServerReflectionInfo", request, {
      scheme = self.scheme,
      authority = self.authority,
      timeout = self.timeout,
    })
  if not stream then
    return nil, err
  end
  if stream.headers[":status"] ~= "200" then
    return nil, ("gRPC returned HTTP status %s"):format(
      tostring(stream.headers[":status"]))
  end
  local grpc_status = stream.headers["grpc-status"]
  if grpc_status and grpc_status ~= "0" then
    return nil, ("gRPC status %s: %s"):format(grpc_status,
      stream.headers["grpc-message"] or "")
  end
  local messages, perr = parse_grpc_frames(stream.body,
    stream.headers["grpc-encoding"])
  if not messages then
    return nil, perr
  end
  local responses = {}
  for _, message in ipairs(messages) do
    local response
    response, err = self:parse_response(message)
    if not response then
      return nil, err
    end
    responses[#responses + 1] = response
  end
  return responses
end

function Reflection:list_services()
  local responses, err = self:call("list_services")
  if not responses then
    return nil, err
  end
  local seen = {}
  local services = {}
  for _, response in ipairs(responses) do
    for _, name in ipairs(response.services or {}) do
      if not seen[name] then
        seen[name] = true
        services[#services + 1] = name
      end
    end
  end
  return services
end

function Reflection:file_containing_symbol(symbol)
  local responses, err = self:call("file_containing_symbol", symbol)
  if not responses then
    return nil, err
  end
  local descriptors = {}
  for _, response in ipairs(responses) do
    for _, descriptor in ipairs(response.descriptors or {}) do
      descriptors[#descriptors + 1] = descriptor
    end
  end
  return descriptors
end

local function reflection_connect(http2, options)
  local last_error
  for _, service in ipairs(REFLECTION_SERVICES) do
    local reflection = Reflection:new(http2, options)
    reflection.service = service
    reflection.scheme = options.scheme or "http"
    local services, err = reflection:list_services()
    if services then
      return reflection, services
    end
    last_error = err
    stdnse.debug2("gRPC reflection service %s failed: %s", service, err)
  end
  return nil, last_error
end

local PROTO_TYPES = {
  [1] = "double",
  [2] = "float",
  [3] = "int64",
  [4] = "uint64",
  [5] = "int32",
  [6] = "fixed64",
  [7] = "fixed32",
  [8] = "bool",
  [9] = "string",
  [10] = "group",
  [11] = "message",
  [12] = "bytes",
  [13] = "uint32",
  [14] = "enum",
  [15] = "sfixed32",
  [16] = "sfixed64",
  [17] = "sint32",
  [18] = "sint64",
}

local function parse_field_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  return {
    name = pb_value(fields, 1),
    extendee = pb_value(fields, 2),
    number = pb_value(fields, 3),
    label = pb_value(fields, 4),
    type = pb_value(fields, 5),
    type_name = pb_value(fields, 6),
    default_value = pb_value(fields, 7),
    oneof_index = pb_value(fields, 9),
    json_name = pb_value(fields, 10),
    proto3_optional = pb_value(fields, 17) == 1,
  }
end

local function parse_enum_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  local values = {}
  for _, value_data in ipairs(pb_values(fields, 2)) do
    local value_fields, verr = pb_message(value_data)
    if not value_fields then
      return nil, verr
    end
    values[#values + 1] = {
      name = pb_value(value_fields, 1),
      number = pb_value(value_fields, 2),
    }
  end
  return {
    name = pb_value(fields, 1),
    values = values,
  }
end

local function parse_message_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  local message = {
    name = pb_value(fields, 1),
    fields = {},
    nested = {},
    enums = {},
    oneofs = {},
    map_entry = false,
  }
  for _, field_data in ipairs(pb_values(fields, 2)) do
    local field, ferr = parse_field_descriptor(field_data)
    if not field then
      return nil, ferr
    end
    message.fields[#message.fields + 1] = field
  end
  for _, nested_data in ipairs(pb_values(fields, 3)) do
    local nested, nerr = parse_message_descriptor(nested_data)
    if not nested then
      return nil, nerr
    end
    message.nested[#message.nested + 1] = nested
  end
  for _, enum_data in ipairs(pb_values(fields, 4)) do
    local enum, eerr = parse_enum_descriptor(enum_data)
    if not enum then
      return nil, eerr
    end
    message.enums[#message.enums + 1] = enum
  end
  for _, oneof_data in ipairs(pb_values(fields, 8)) do
    local oneof_fields, oerr = pb_message(oneof_data)
    if not oneof_fields then
      return nil, oerr
    end
    message.oneofs[#message.oneofs + 1] = {
      name = pb_value(oneof_fields, 1),
    }
  end
  local options = pb_value(fields, 7)
  if options then
    local option_fields = pb_message(options)
    if option_fields and pb_value(option_fields, 7) == 1 then
      message.map_entry = true
    end
  end
  return message
end

local function parse_method_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  return {
    name = pb_value(fields, 1),
    input_type = pb_value(fields, 2),
    output_type = pb_value(fields, 3),
    client_streaming = pb_value(fields, 5) == 1,
    server_streaming = pb_value(fields, 6) == 1,
  }
end

local function parse_service_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  local service = {
    name = pb_value(fields, 1),
    methods = {},
  }
  for _, method_data in ipairs(pb_values(fields, 2)) do
    local method, merr = parse_method_descriptor(method_data)
    if not method then
      return nil, merr
    end
    service.methods[#service.methods + 1] = method
  end
  return service
end

local function parse_file_descriptor(data)
  local fields, err = pb_message(data)
  if not fields then
    return nil, err
  end
  local file = {
    name = pb_value(fields, 1),
    package = pb_value(fields, 2) or "",
    dependencies = pb_values(fields, 3),
    messages = {},
    enums = {},
    services = {},
    syntax = pb_value(fields, 12),
    edition = pb_value(fields, 14),
    public_dependency = {},
    weak_dependency = {},
  }
  for _, dependency in ipairs(pb_values(fields, 10)) do
    file.public_dependency[dependency + 1] = true
  end
  for _, dependency in ipairs(pb_values(fields, 11)) do
    file.weak_dependency[dependency + 1] = true
  end
  for _, message_data in ipairs(pb_values(fields, 4)) do
    local message, merr = parse_message_descriptor(message_data)
    if not message then
      return nil, merr
    end
    file.messages[#file.messages + 1] = message
  end
  for _, enum_data in ipairs(pb_values(fields, 5)) do
    local enum, eerr = parse_enum_descriptor(enum_data)
    if not enum then
      return nil, eerr
    end
    file.enums[#file.enums + 1] = enum
  end
  for _, service_data in ipairs(pb_values(fields, 6)) do
    local service, serr = parse_service_descriptor(service_data)
    if not service then
      return nil, serr
    end
    file.services[#file.services + 1] = service
  end
  return file
end

local function strip_type_name(name)
  return name and string.gsub(name, "^%.", "") or name
end

local function index_descriptors(files)
  local registry = {}
  local function add_message(prefix, message)
    local full_name = prefix .. message.name
    message.full_name = full_name
    registry[full_name] = message
    for _, nested in ipairs(message.nested) do
      add_message(full_name .. ".", nested)
    end
  end
  local function add_enum(prefix, enum)
    enum.full_name = prefix .. enum.name
    registry[enum.full_name] = enum
  end
  for _, file in ipairs(files) do
    local prefix = file.package ~= "" and (file.package .. ".") or ""
    for _, message in ipairs(file.messages) do
      add_message(prefix, message)
    end
    for _, enum in ipairs(file.enums) do
      add_enum(prefix, enum)
    end
    for _, service in ipairs(file.services) do
      service.full_name = prefix .. service.name
      registry[service.full_name] = service
    end
  end
  return registry
end

local function field_type(field, registry)
  if field.type == 11 or field.type == 14 then
    return strip_type_name(field.type_name) or "unknown"
  end
  return PROTO_TYPES[field.type] or ("type_" .. tostring(field.type))
end

local function map_entry_for(field, registry)
  if field.label ~= 3 or field.type ~= 11 or not field.type_name then
    return nil
  end
  local entry = registry[strip_type_name(field.type_name)]
  if entry and entry.map_entry then
    return entry
  end
  return nil
end

local function proto_quote(value)
  return '"' .. string.gsub(value, "\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n") .. '"'
end

local function render_field(field, registry, syntax, in_oneof)
  local entry = map_entry_for(field, registry)
  if entry and entry.fields[1] and entry.fields[2] then
    return ("map<%s, %s> %s = %d;"):format(
      field_type(entry.fields[1], registry),
      field_type(entry.fields[2], registry),
      field.name, field.number)
  end
  local label = ""
  if field.label == 3 then
    label = "repeated "
  elseif not in_oneof and field.label == 2 then
    label = "required "
  elseif not in_oneof and (syntax ~= "proto3" or field.proto3_optional) then
    label = "optional "
  end
  local line = ("%s%s %s = %d"):format(
    label, field_type(field, registry), field.name, field.number)
  if field.default_value then
    local value = field.default_value
    if field.type == 9 or field.type == 12 then
      value = proto_quote(value)
    end
    line = line .. (" [default = %s]"):format(value)
  end
  return line .. ";"
end

local function oneof_is_synthetic(message, index)
  local count = 0
  local optional = false
  for _, field in ipairs(message.fields) do
    if field.oneof_index == index then
      count = count + 1
      optional = optional or field.proto3_optional
    end
  end
  return count == 1 and optional
end

local render_message

local function render_enum(enum, indent, lines)
  lines[#lines + 1] = indent .. "enum " .. enum.name .. " {"
  for _, value in ipairs(enum.values) do
    lines[#lines + 1] = indent .. "  " .. value.name .. " = " .. tostring(value.number) .. ";"
  end
  lines[#lines + 1] = indent .. "}"
end

render_message = function(message, registry, syntax, indent, lines)
  lines[#lines + 1] = indent .. "message " .. message.name .. " {"
  local inner = indent .. "  "
  local synthetic = {}
  for index, oneof in ipairs(message.oneofs) do
    synthetic[index - 1] = oneof_is_synthetic(message, index - 1)
  end
  for _, field in ipairs(message.fields) do
    if field.oneof_index == nil or synthetic[field.oneof_index] then
      lines[#lines + 1] = inner .. render_field(field, registry, syntax, false)
    end
  end
  for index, oneof in ipairs(message.oneofs) do
    if not synthetic[index - 1] then
      lines[#lines + 1] = inner .. "oneof " .. oneof.name .. " {"
      for _, field in ipairs(message.fields) do
        if field.oneof_index == index - 1 then
          lines[#lines + 1] = inner .. "  " .. render_field(
            field, registry, syntax, true)
        end
      end
      lines[#lines + 1] = inner .. "}"
    end
  end
  for _, enum in ipairs(message.enums) do
    render_enum(enum, inner, lines)
  end
  for _, nested in ipairs(message.nested) do
    if not nested.map_entry then
      render_message(nested, registry, syntax, inner, lines)
    end
  end
  lines[#lines + 1] = indent .. "}"
end

local function render_service(service, indent, lines)
  lines[#lines + 1] = indent .. "service " .. service.name .. " {"
  for _, method in ipairs(service.methods) do
    local input = strip_type_name(method.input_type) or "unknown"
    local output = strip_type_name(method.output_type) or "unknown"
    if method.client_streaming then
      input = "stream " .. input
    end
    if method.server_streaming then
      output = "stream " .. output
    end
    lines[#lines + 1] = ("%s  rpc %s (%s) returns (%s);"):format(
      indent, method.name, input, output)
  end
  lines[#lines + 1] = indent .. "}"
end

local function render_file(file, registry)
  local lines = {}
  if file.syntax == "proto3" then
    lines[#lines + 1] = 'syntax = "proto3";'
  elseif file.syntax then
    lines[#lines + 1] = ('syntax = "%s";'):format(file.syntax)
  end
  if file.package ~= "" then
    lines[#lines + 1] = "package " .. file.package .. ";"
  end
  for index, dependency in ipairs(file.dependencies) do
    local kind = ""
    if file.public_dependency[index] then
      kind = " public"
    elseif file.weak_dependency[index] then
      kind = " weak"
    end
    lines[#lines + 1] = ('import%s "%s";'):format(kind, dependency)
  end
  if #lines > 0 then
    lines[#lines + 1] = ""
  end
  for _, enum in ipairs(file.enums) do
    render_enum(enum, "", lines)
    lines[#lines + 1] = ""
  end
  for _, message in ipairs(file.messages) do
    render_message(message, registry, file.syntax, "", lines)
    lines[#lines + 1] = ""
  end
  for _, service in ipairs(file.services) do
    render_service(service, "", lines)
    lines[#lines + 1] = ""
  end
  while lines[#lines] == "" do
    lines[#lines] = nil
  end
  return table.concat(lines, "\n")
end

local function service_summaries(files)
  local summaries = {}
  for _, file in ipairs(files) do
    for _, service in ipairs(file.services) do
      local service_name = service.full_name or service.name
      for _, method in ipairs(service.methods) do
        summaries[#summaries + 1] = ("%s.%s(%s%s) returns (%s%s)"):format(
          service_name,
          method.name,
          method.client_streaming and "stream " or "",
          strip_type_name(method.input_type) or "?",
          method.server_streaming and "stream " or "",
          strip_type_name(method.output_type) or "?")
      end
      if #service.methods == 0 then
        summaries[#summaries + 1] = service_name
      end
    end
  end
  return summaries
end

local function descriptor_files(descriptor_data)
  local files = {}
  local seen = {}
  for _, data in ipairs(descriptor_data) do
    local file, err = parse_file_descriptor(data)
    if not file then
      return nil, err
    end
    local key = file.name or ("descriptor-" .. tostring(#files + 1))
    if not seen[key] then
      seen[key] = true
      files[#files + 1] = file
    end
  end
  return files
end

local function host_authority(host, port, scheme)
  local name = host.targetname
  if not name or name == "" then
    name = stdnse.get_hostname(host)
  end
  if not name or name == "" then
    name = host.ip or tostring(host)
  end
  if string.find(name, ":", 1, true) and not string.find(name, "^%[") then
    name = "[" .. name .. "]"
  end
  local default_port = (scheme == "https") and 443 or 80
  if tonumber(port.number) ~= default_port then
    name = name .. ":" .. tostring(port.number)
  end
  return name
end

local function open_http2(host, port, scheme, options)
  local socket = nmap.new_socket()
  if scheme == "https" and socket.set_alpn then
    local status, err = socket:set_alpn("h2")
    if not status then
      socket:close()
      return nil, nil, err
    end
  end
  local status, err = socket:connect(host, port,
    scheme == "https" and "ssl" or "tcp")
  if not status then
    socket:close()
    return nil, nil, err
  end
  socket:set_timeout(options.timeout)
  local http2 = HTTP2:new(socket)
  status, err = http2:handshake()
  if not status then
    socket:close()
    return nil, nil, err
  end
  return http2, socket
end

--- Connects to a gRPC server and initializes the reflection API.
--
-- The function first tries cleartext HTTP/2 (h2c) unless the port is known to
-- be TLS. If that fails and TLS was not ruled out, it retries over TLS.
--
-- @param host NSE host table.
-- @param port NSE port table.
-- @param options Optional table. Supported keys are <code>timeout</code>
--                (milliseconds) and <code>scheme</code> ("http" or "https").
-- @return Reflection client, service list, HTTP/2 client, socket, or nil and
--         an error message.
function connect(host, port, options)
  options = options or {}
  local timeout = tonumber(options.timeout) or DEFAULT_TIMEOUT
  local schemes = {}
  if options.scheme then
    schemes[1] = options.scheme
  elseif (port.version and port.version.service_tunnel == "ssl")
    or shortport.ssl(host, port) then
    schemes[1] = "https"
  else
    schemes = { "http", "https" }
  end

  local last_error = "gRPC reflection unavailable"
  for _, scheme in ipairs(schemes) do
    local authority = host_authority(host, port, scheme)
    local http2, socket, err = open_http2(host, port, scheme, {
      timeout = timeout,
    })
    if http2 then
      local reflection, services
      reflection, services = reflection_connect(http2, {
        authority = authority,
        host = options.host or "",
        timeout = timeout,
        scheme = scheme,
      })
      if reflection then
        return reflection, services, http2, socket
      end
      last_error = services
      socket:close()
    else
      last_error = err
    end
    stdnse.debug2("gRPC %s probe failed: %s", scheme, last_error)
  end
  return nil, last_error
end

--- Enumerates gRPC services and retrieves their protobuf descriptors.
--
-- @param host NSE host table.
-- @param port NSE port table.
-- @param options Optional connection options (see <code>connect</code>).
-- @return Result table or nil and an error message.
function discover(host, port, options)
  options = options or {}
  local reflection, services, http2, socket = connect(host, port, options)
  if not reflection then
    return nil, services
  end

  local descriptor_data = {}
  local seen_data = {}
  local errors = {}
  for _, service in ipairs(services) do
    local data, err = reflection:file_containing_symbol(service)
    if data then
      for _, descriptor in ipairs(data) do
        if not seen_data[descriptor] then
          seen_data[descriptor] = true
          descriptor_data[#descriptor_data + 1] = descriptor
        end
      end
    else
      errors[#errors + 1] = ("%s: %s"):format(service, tostring(err))
      stdnse.debug2("gRPC descriptor request for %s failed: %s", service, err)
    end
  end
  socket:close()

  local files, err = descriptor_files(descriptor_data)
  if not files then
    return nil, "failed to parse protobuf descriptors: " .. tostring(err)
  end
  local registry = index_descriptors(files)
  for _, file in ipairs(files) do
    file.proto = render_file(file, registry)
  end
  return {
    services = services,
    files = files,
    summaries = service_summaries(files),
    errors = errors,
    reflection_service = reflection.service,
    scheme = reflection.scheme,
  }
end

--- Parses protobuf FileDescriptorProto bytes.
-- @param data Encoded FileDescriptorProto.
-- @return Parsed descriptor table or nil and an error.
function parse_descriptor(data)
  return parse_file_descriptor(data)
end

--- Renders parsed FileDescriptorProto tables as .proto source.
-- @param files Array of parsed FileDescriptorProto tables.
-- @return Array of strings, one for each file.
function render_descriptors(files)
  local registry = index_descriptors(files)
  local rendered = {}
  for _, file in ipairs(files) do
    rendered[#rendered + 1] = {
      name = file.name,
      proto = render_file(file, registry),
    }
  end
  return rendered
end

--- Decodes an HPACK header block.
-- @param data HPACK block.
-- @return Array of <code>{name, value}</code> tables or nil and an error.
function decode_headers(data)
  return HPACK:new():decode(data)
end

--- Encodes headers using HPACK literal-only representations.
-- @param headers Array of <code>{name, value}</code> tables.
-- @return HPACK block.
function encode_headers(headers)
  local converted = {}
  for _, header in ipairs(headers) do
    converted[#converted + 1] = {
      name = header.name or header[1],
      value = header.value or header[2],
    }
  end
  return HPACK:new():encode(converted)
end

--- Encodes an HTTP/2 frame.
-- @param frame_type Frame type byte.
-- @param flags Frame flags.
-- @param stream_id Stream identifier.
-- @param payload Frame payload.
-- @return Encoded frame.
function encode_frame(frame_type, flags, stream_id, payload)
  return pack_frame(frame_type, flags, stream_id, payload)
end

--- Creates an HTTP/2 client around a connected NSE socket.
-- This is primarily useful for embedding and testing.
-- @param socket Connected socket object.
-- @param options Optional table.
-- @return HTTP/2 client.
function new_http2(socket, options)
  return HTTP2:new(socket, options)
end

--- Parses a nine-byte HTTP/2 frame header.
-- @param header Frame header bytes.
-- @return Frame header table or nil and an error.
function parse_frame_header(header)
  return unpack_frame_header(header)
end

--- Decodes a ServerReflectionResponse protobuf message.
-- @param data Encoded response.
-- @return Response table or nil and an error.
function decode_reflection_response(data)
  local reflection = setmetatable({}, { __index = Reflection })
  return reflection:parse_response(data)
end

--- Encodes a protobuf varint.
function varint(value)
  return encode_varint(value)
end

-- Public helpers used by scripts and unit tests.
parse_grpc_frames = parse_grpc_frames
grpc_frame = grpc_frame
encode_pb_bytes = encode_pb_bytes
encode_pb_varint = encode_pb_varint
parse_pb = parse_pb
parse_file_descriptor = parse_file_descriptor

if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

local function encoded_varint_roundtrip(value)
  local encoded = varint(value)
  local decoded, pos = decode_varint(encoded, 1)
  return decoded == value and pos == #encoded + 1
end

for _, value in ipairs({ 0, 1, 127, 128, 300, 16384, 0x7fffffff }) do
  test_suite:add_test(function()
    return encoded_varint_roundtrip(value)
  end,
    ("protobuf varint roundtrip %d"):format(value))
end

local pb_data = encode_pb_bytes(1, "hello") .. encode_pb_varint(2, 42)
local pb_fields = parse_pb(pb_data)
test_suite:add_test(unittest.is_true(pb_fields ~= nil), "protobuf message parses")
test_suite:add_test(unittest.equal(pb_value(pb_fields, 1), "hello"),
  "protobuf string field")
test_suite:add_test(unittest.equal(pb_value(pb_fields, 2), 42),
  "protobuf varint field")

local framed = grpc_frame("abc") .. grpc_frame("defg")
local grpc_messages, grpc_err = parse_grpc_frames(framed)
test_suite:add_test(unittest.is_true(grpc_messages ~= nil),
  "gRPC stream parses: " .. tostring(grpc_err))
test_suite:add_test(unittest.table_equal(grpc_messages or {}, { "abc", "defg" }),
  "gRPC stream message bodies")
local truncated_messages = parse_grpc_frames("\0\0\0")
test_suite:add_test(unittest.is_nil(truncated_messages),
  "truncated gRPC stream is rejected")

local static_headers = decode_headers("\x82")
test_suite:add_test(unittest.equal(static_headers[1].name, ":method"),
  "HPACK static indexed name")
test_suite:add_test(unittest.equal(static_headers[1].value, "GET"),
  "HPACK static indexed value")

local huffman_value = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"
local huffman_headers = decode_headers("\x01\x8c" .. huffman_value)
test_suite:add_test(unittest.equal(huffman_headers[1].name, ":authority"),
  "HPACK Huffman header name")
test_suite:add_test(unittest.equal(huffman_headers[1].value, "www.example.com"),
  "HPACK Huffman header value")

local dynamic_headers = decode_headers(
  "\x40\x0acustom-key\x0ccustom-value\xbe")
test_suite:add_test(unittest.equal(dynamic_headers[2].name, "custom-key"),
  "HPACK dynamic table name")
test_suite:add_test(unittest.equal(dynamic_headers[2].value, "custom-value"),
  "HPACK dynamic table value")

local frame = encode_frame(FRAME.HEADERS, FLAG.END_HEADERS, 1, "abc")
local frame_header = parse_frame_header(string.sub(frame, 1, 9))
test_suite:add_test(unittest.equal(#frame, 12), "HTTP/2 frame length")
test_suite:add_test(unittest.equal(frame_header.type, FRAME.HEADERS),
  "HTTP/2 frame type")
test_suite:add_test(unittest.equal(frame_header.flags, FLAG.END_HEADERS),
  "HTTP/2 frame flags")
test_suite:add_test(unittest.equal(frame_header.stream_id, 1),
  "HTTP/2 frame stream id")
test_suite:add_test(unittest.equal(string.sub(frame, 10), "abc"),
  "HTTP/2 frame payload")

local list_service = encode_pb_bytes(1, "helloworld.Greeter")
local list_response = encode_pb_bytes(1, list_service)
local decoded_list = decode_reflection_response(encode_pb_bytes(6, list_response))
test_suite:add_test(unittest.equal(decoded_list.services[1], "helloworld.Greeter"),
  "reflection list_services response")

local reflection_error = encode_pb_varint(1, 12)
  .. encode_pb_bytes(2, "not implemented")
local decoded_error, reflection_error_text = decode_reflection_response(
  encode_pb_bytes(7, reflection_error))
test_suite:add_test(unittest.is_nil(decoded_error),
  "reflection error response is rejected")
test_suite:add_test(unittest.is_true(
  reflection_error_text:find("not implemented", 1, true) ~= nil),
  "reflection error message is preserved")

local function descriptor_field(name, number, field_type, type_name, label)
  local data = encode_pb_bytes(1, name)
    .. encode_pb_varint(3, number)
    .. encode_pb_varint(4, label or 1)
    .. encode_pb_varint(5, field_type)
  if type_name then
    data = data .. encode_pb_bytes(6, type_name)
  end
  return data
end

local request_message = encode_pb_bytes(1, "HelloRequest")
  .. encode_pb_bytes(2, descriptor_field("name", 1, 9))
local reply_message = encode_pb_bytes(1, "HelloReply")
  .. encode_pb_bytes(2, descriptor_field("message", 1, 9))
local method = encode_pb_bytes(1, "SayHello")
  .. encode_pb_bytes(2, ".helloworld.HelloRequest")
  .. encode_pb_bytes(3, ".helloworld.HelloReply")
local service = encode_pb_bytes(1, "Greeter")
  .. encode_pb_bytes(2, method)
local descriptor = encode_pb_bytes(1, "helloworld.proto")
  .. encode_pb_bytes(2, "helloworld")
  .. encode_pb_bytes(4, request_message)
  .. encode_pb_bytes(4, reply_message)
  .. encode_pb_bytes(6, service)
  .. encode_pb_bytes(12, "proto3")

local parsed_descriptor, descriptor_err = parse_descriptor(descriptor)
test_suite:add_test(unittest.is_true(parsed_descriptor ~= nil),
  "FileDescriptorProto parses: " .. tostring(descriptor_err))
local rendered = render_descriptors({ parsed_descriptor })
local proto = rendered[1].proto
local expected_proto = {
  'syntax = "proto3";',
  "package helloworld;",
  "message HelloRequest {",
  "  string name = 1;",
  "message HelloReply {",
  "  string message = 1;",
  "service Greeter {",
  "  rpc SayHello (helloworld.HelloRequest) returns (helloworld.HelloReply);",
}
for _, expected in ipairs(expected_proto) do
  test_suite:add_test(unittest.is_true(proto:find(expected, 1, true) ~= nil),
    "descriptor renders " .. expected)
end

local descriptor_response = decode_reflection_response(
  encode_pb_bytes(4, encode_pb_bytes(1, descriptor)))
test_suite:add_test(unittest.equal(descriptor_response.descriptors[1], descriptor),
  "reflection file_descriptor_response")

local FakeSocket = {}
FakeSocket.__index = FakeSocket

function FakeSocket:new(data, chunk_size)
  return setmetatable({
    data = data,
    pos = 1,
    chunk_size = chunk_size or 7,
    sent = {},
  }, self)
end

function FakeSocket:send(data)
  self.sent[#self.sent + 1] = data
  return true
end

function FakeSocket:receive()
  if self.pos > #self.data then
    return false, "TIMEOUT"
  end
  local chunk = string.sub(self.data, self.pos, self.pos + self.chunk_size - 1)
  self.pos = self.pos + #chunk
  return true, chunk
end

local fake_headers = encode_headers({
  { name = ":status", value = "200" },
  { name = "content-type", value = "application/grpc" },
})
local fake_trailers = encode_headers({
  { name = "grpc-status", value = "0" },
})
local fake_server_data = encode_frame(4, 0, 0, "")
  .. encode_frame(1, 4, 1, fake_headers)
  .. encode_frame(0, 0, 1, grpc_frame("response"))
  .. encode_frame(1, 5, 1, fake_trailers)
local fake_socket = FakeSocket:new(fake_server_data, 7)
local fake_http2 = new_http2(fake_socket)
local handshake_ok = fake_http2:handshake()
local fake_stream, fake_err = fake_http2:request("/test.Service/Method", "request", {
  authority = "localhost",
  scheme = "http",
})
test_suite:add_test(unittest.is_true(handshake_ok ~= nil),
  "HTTP/2 handshake writes")
test_suite:add_test(unittest.is_true(fake_stream ~= nil),
  "HTTP/2 request over fragmented reads: " .. tostring(fake_err))
test_suite:add_test(unittest.equal(fake_stream and fake_stream.headers[":status"], "200"),
  "HTTP/2 response status")
test_suite:add_test(unittest.equal(fake_stream and fake_stream.headers["grpc-status"], "0"),
  "HTTP/2 trailers received")
test_suite:add_test(unittest.equal(fake_stream and fake_stream.body, grpc_frame("response")),
  "HTTP/2 response body")
test_suite:add_test(unittest.is_true(fake_socket.sent[1] == HTTP2_PREFACE),
  "HTTP/2 client preface")

local alpn_socket = nmap.new_socket()
local alpn_ok, alpn_err = alpn_socket:set_alpn({"h2", "http/1.1"})
test_suite:add_test(unittest.is_true(alpn_ok ~= nil),
  "socket:set_alpn accepts a protocol list: " .. tostring(alpn_err))
alpn_ok, alpn_err = alpn_socket:set_alpn(nil)
test_suite:add_test(unittest.is_true(alpn_ok ~= nil),
  "socket:set_alpn clears the protocol list: " .. tostring(alpn_err))

return _ENV

