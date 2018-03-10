"use strict";
exports.__esModule = true;
var bs32 = require("thirty-two");
var crypto = require("crypto");
function hexToBytes(hex) {
    var bytes = [];
    for (var c = 0, C = hex.length; c < C; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}
function getOtpSecret(size) {
    if (size === void 0) { size = 16; }
    var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz!@#$%^&*()<>?/[]{},.:;';
    var res = '';
    while (res.length < size) {
        res += set[Math.floor(Math.random() * set.length)];
    }
    return bs32.encode(res).toString().replace(/=/g, '');
}
exports.getOtpSecret = getOtpSecret;
function getGoogleTotpUri(secret, sp, user) {
    if (sp === void 0) { sp = "app"; }
    var protocol = "otpauth://";
    var type = "totp";
    var res = "" + protocol + type + "/" + sp + ":" + user + "?secret=" + secret;
    return res;
}
exports.getGoogleTotpUri = getGoogleTotpUri;
function getOtpCode(secret, expire) {
    if (expire === void 0) { expire = 30; }
    var step = Math.floor(Date.now() / (expire * 1000)).toString();
    var hash = crypto.createHmac("sha1", secret).update(step).digest("hex");
    var h = hexToBytes(hash);
    var offset = h[19] & 0xf;
    var v = (h[offset] & 0x7f) << 24 |
        (h[offset + 1] & 0xff) << 16 |
        (h[offset + 2] & 0xff) << 8 |
        (h[offset + 3] & 0xff) % 1000000;
    return Array(7 - String(v).length).join('0') + String(v);
}
exports.getOtpCode = getOtpCode;
function checkCodeFromClient(secret, code) {
    var serverCode = getOtpCode(secret);
    var res = serverCode === String(code);
    return res;
}
exports.checkCodeFromClient = checkCodeFromClient;
