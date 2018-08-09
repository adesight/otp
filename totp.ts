import * as bs32 from "thirty-two";
import { createHmac, randomBytes } from "crypto";

function hexToBytes(hex) {
  var bytes = [];
  for (var c = 0, C = hex.length; c < C; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return bytes;
}

export function getOtpSecret(size: number = 16): string {
  return bs32
    .encode(randomBytes(size))
    .toString()
    .replace(/=/g, "");
}

/**
 * format
 * otpauth://TYPE/LABEL?PARAMETERS
 * TYPE 支持 hotp 或 totp；
 * LABEL 用来指定用户身份，例如用户名、邮箱或者手机号，前面还可以加上服务提供者，需要做 URI 编码。它是给人看的，不影响最终校验码的生成。
 * PARAMETERS 类似 querystring，可包含以下字段
 * secret：必须，密钥 K，需要编码为 base32 格式；
 * algorithm：可选，HMAC 的哈希算法，默认 SHA1。Google Authenticator 不支持这个参数；
 * digits：可选，校验码长度，6 位或 8 位，默认 6 位。Google Authenticator 不支持这个参数；
 * counter：可选，指定 HOTP 算法中，计数器 C 的默认值，默认 0；
 * period：可选，指定 TOTP 算法中的间隔时间 TS，默认 30 秒。Google Authenticator 不支持这个参数；
 * issuer：可选（强烈推荐），指定服务提供者。这个字段会在 Google Authenticator 客户端中单独显示，在添加了多个服务者提供的 2FA 后特别有用；
 * 详细参考： https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function getGoogleTotpUri(
  secret: string,
  user: string = "",
  type: string = "totp",
  sp: string = "app"
): string {
  // sp = 服务提供者
  return `otpauth://${type}/${sp}:${user}?secret=${secret}`;
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
  const step: string = Math.floor(Date.now() / (expire * 1000)).toString();
  const hash: string = createHmac("sha1", secret)
    .update(step)
    .digest("hex");
  var h = hexToBytes(hash);
  var offset = h[19] & 0xf;
  const v =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff) % 1000000;

  return String(v).padStart(6, "0");
}

export function checkCodeFromClient(
  secret: string,
  code: string | number
): boolean {
  const serverCode = getOtpCode(secret);
  const res = serverCode === String(code);
  return res;
}
