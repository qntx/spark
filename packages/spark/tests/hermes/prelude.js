// Concatenated ahead of the smoke bundle by scripts/hermes-smoke.ts when
// HERMES_ENCODING_SHIM=1 (local runs against an older Hermes only).
// RN 0.86-era Hermes has no TextEncoder/TextDecoder; protobuf-es needs both at
// module load. These minimal UTF-8 shims only install when the runtime lacks
// the globals — on RN 0.88+ Hermes the native implementations win.
(function () {
  if (
    typeof globalThis.TextEncoder !== "undefined" &&
    typeof globalThis.TextDecoder !== "undefined"
  ) {
    return;
  }
  function encode(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var d = str.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) {
          c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
          i++;
        }
      }
      if (c < 0x80) bytes.push(c);
      else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else if (c < 0x10000)
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      else
        bytes.push(
          0xf0 | (c >> 18),
          0x80 | ((c >> 12) & 0x3f),
          0x80 | ((c >> 6) & 0x3f),
          0x80 | (c & 0x3f),
        );
    }
    return Uint8Array.from(bytes);
  }
  function decode(bytes) {
    var result = "";
    for (var i = 0; i < bytes.length;) {
      var b = bytes[i];
      var code = 0,
        length = 1;
      if (b < 0x80) code = b;
      else if ((b & 0xe0) === 0xc0) {
        code = b & 0x1f;
        length = 2;
      } else if ((b & 0xf0) === 0xe0) {
        code = b & 0x0f;
        length = 3;
      } else if ((b & 0xf8) === 0xf0) {
        code = b & 0x07;
        length = 4;
      } else code = 0xfffd;
      for (var j = 1; j < length; j++) {
        if (i + j >= bytes.length || (bytes[i + j] & 0xc0) !== 0x80) {
          code = 0xfffd;
          break;
        }
        code = (code << 6) | (bytes[i + j] & 0x3f);
      }
      result += String.fromCodePoint(code > 0x10ffff ? 0xfffd : code);
      i += length;
    }
    return result;
  }
  if (typeof globalThis.TextEncoder === "undefined") {
    globalThis.TextEncoder = function TextEncoder() {};
    globalThis.TextEncoder.prototype.encode = encode;
    globalThis.TextEncoder.prototype.encodeInto = function (str, dest) {
      var bytes = encode(str);
      var written = Math.min(bytes.length, dest.length);
      dest.set(bytes.subarray(0, written));
      return { read: str.length, written: written };
    };
  }
  if (typeof globalThis.TextDecoder === "undefined") {
    globalThis.TextDecoder = function TextDecoder() {};
    globalThis.TextDecoder.prototype.decode = function (input) {
      return input === undefined ? "" : decode(input);
    };
  }
})();
