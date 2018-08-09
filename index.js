"use strict";
exports.__esModule = true;
var bs32 = require("thirty-two");
var crypto_1 = require("crypto");
function hexToBytes(hex) {
    var bytes = [];
    for (var c = 0, C = hex.length; c < C; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}
function getOtpSecret(size) {
    if (size === void 0) { size = 16; }
    return bs32
        .encode(crypto_1.randomBytes(size))
        .toString()
        .replace(/=/g, "");
}
exports.getOtpSecret = getOtpSecret;
function getGoogleTotpUri(secret, user, type, sp) {
    if (user === void 0) { user = ""; }
    if (type === void 0) { type = "totp"; }
    if (sp === void 0) { sp = "app"; }
    return "otpauth://" + type + "/" + sp + ":" + user + "?secret=" + secret;
}
exports.getGoogleTotpUri = getGoogleTotpUri;
function getOtpCode(secret, expire) {
    if (expire === void 0) { expire = 30; }
    var step = Math.floor(Date.now() / (expire * 1000)).toString();
    var hash = crypto_1.createHmac("sha1", secret)
        .update(step)
        .digest("hex");
    var h = hexToBytes(hash);
    var offset = h[19] & 0xf;
    var v = ((h[offset] & 0x7f) << 24) |
        ((h[offset + 1] & 0xff) << 16) |
        ((h[offset + 2] & 0xff) << 8) |
        (h[offset + 3] & 0xff) % 1000000;
    return String(v).padStart(6, "0");
}
exports.getOtpCode = getOtpCode;
function checkCodeFromClient(secret, code) {
    var serverCode = getOtpCode(secret);
    var res = serverCode === String(code);
    return res;
}
exports.checkCodeFromClient = checkCodeFromClient;
