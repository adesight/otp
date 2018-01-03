"use strict";
exports.__esModule = true;
var random_numorstr_1 = require("random-numorstr");
var bs32 = require("base32");
var crypto = require("crypto");
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
    var lastLetterOfHash = parseInt(hash[hash.length - 1], 16);
    var slice = hash.substring(lastLetterOfHash + 1, 8);
    var hex = parseInt(slice, 16);
    var res = String(hex % 1000000);
    while (res.length < 6) {
        res = "0" + res;
    }
    return res;
}
exports.getOtpCode = getOtpCode;
function checkCodeFromClient(secret, code) {
    var serverCode = getOtpCode(secret);
    var res = serverCode === String(code);
    return res;
}
exports.checkCodeFromClient = checkCodeFromClient;
