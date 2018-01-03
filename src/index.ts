import { getSafer as getSaferRandom } from "random-numorstr"
import * as bs32 from "base32"
import * as crypto from "crypto"

export function getOtpSecret(): string {
    const random = getSaferRandom();
    return bs32.encode(random)
}
/**
 * 格式
 * otpauth://TYPE/LABEL?PARAMETERS
 * TYPE 支持 hotp 或 totp；
 * LABEL 用来指定用户身份，例如用户名、邮箱或者手机号，前面还可以加上服务提供者，需要做 URI 编码。
 * PARAMETERS 用来指定参数，它的格式与 URL 的 Query 部分一样，也是由多对 key 和 value 组成，也需要做 URL 编码。可指定的参数有这些：
 * secret：必须，密钥 K，需要编码为 base32 格式；
 * algorithm：可选，HMAC 的哈希算法，默认 SHA1。Google Authenticator 不支持这个参数；
 * digits：可选，校验码长度，6 位或 8 位，默认 6 位。Google Authenticator 不支持这个参数；
 * counter：可选，指定 HOTP 算法中，计数器 C 的默认值，默认 0；
 * period：可选，指定 TOTP 算法中的间隔时间 TS，默认 30 秒。Google Authenticator 不支持这个参数；
 * issuer：可选（强烈推荐），指定服务提供者。这个字段会在 Google Authenticator 客户端中单独显示，在添加了多个服务者提供的 2FA 后特别有用；
 */
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
    const lastLetterOfHash: number = parseInt(hash[hash.length - 1], 16)
    const slice: string = hash.substring(lastLetterOfHash + 1, 8)
    const hex: number = parseInt(slice, 16)
    let res: string = String(hex % 1000000)
    while (res.length < 6) {
        res = "0" + res
    }
    return res
}

export function checkCodeFromClient(secret: string, code: string | number): boolean {
    const serverCode = getOtpCode(secret)
    const res = serverCode === String(code)
    return res
}