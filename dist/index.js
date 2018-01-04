"use strict";
exports.__esModule = true;
var random_numorstr_1 = require("random-numorstr");
var bs32 = require("base32");
var crypto = require("crypto");
function hexToBytes(hex) {
    var bytes = [];
    for (var c = 0, C = hex.length; c < C; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}
function getOtpSecret() {
    var random = random_numorstr_1.getSafer();
    return bs32.encode(random);
}
exports.getOtpSecret = getOtpSecret;
function getGoogleTotpUri(secret, app, user, label) {
    if (app === void 0) { app = "app"; }
    var protocol = "otpauth://";
    var type = "totp";
    var labelStr = label || null;
    var res = "" + protocol + type + app + ":" + user + "?secret=" + secret;
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
