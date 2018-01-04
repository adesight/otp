import { getSafer as getSaferRandom } from "random-numorstr"
import * as bs32 from "base32"
import * as crypto from "crypto"

function hexToBytes(hex) {
    var bytes = [];
    for (var c = 0, C = hex.length; c < C; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}

export function getOtpSecret(): string {
    const random = getSaferRandom();
    return bs32.encode(random)
}

export function getGoogleTotpUri(secret: string, app: string = "app", user: string, label?: string): string {
    const protocol = "otpauth://"
    const type = "totp"
    const labelStr = label || null
    const res = `${protocol}${type}${app}:${user}?secret=${secret}`
    return res
}

/**
 * TOTP = Trunc(HMAC-SHA-1(K,T))
 * K是客户端和服务端使用的共享密钥，每个客户端的K应该都是唯一的。
 * T 可以保证 X 秒内客户端和服务器生成的待加密内容一致
 * otp steps:
 * 1. 计算 T = floor((Current Unix time - T0) / X)
 * 2. 使用HMAC-SHA-1算法，利用T和K，生成一个长度为20比特的40个十六进制字符，即：HS = HMAC-SHA-1(K,T)
 * 3. 取上一步最后一位转化为十进制记作 X ，然后对上述字符串进行从0开始两两分组，取 X 组加上后3组共 8 位
 * 4. 取上一步结果转化为十进制，只要六位数字，所以对一百万进行取模即可。如果结果不是六位数字前置补零。
 */
export function getOtpCode(secret: string, expire: number = 30): string {
    const step: string = Math.floor(Date.now() / (expire * 1000)).toString()
    const hash: string = crypto.createHmac("sha1", secret).update(step).digest("hex")
    var h = hexToBytes(hash);
    var offset = h[19] & 0xf;
    const v = (h[offset] & 0x7f) << 24 |
        (h[offset + 1] & 0xff) << 16 |
        (h[offset + 2] & 0xff) << 8 |
        (h[offset + 3] & 0xff) % 1000000;
    return Array(7 - String(v).length).join('0') + String(v)
}

export function checkCodeFromClient(secret: string, code: string | number): boolean {
    const serverCode = getOtpCode(secret)
    const res = serverCode === String(code)
    return res
}