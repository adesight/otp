# OTP
one-time password for Node.js

# Usage

```js
import {
    getGoogleTotpUri,
    getOtpSecret,
    getOtpCode,
    checkCodeFromClient
} from './dist/index.js'

// get otp string
const secretForClient = getOtpSecret();
const totpUri = getGoogleTotpUri("secret", "service provider", "user identifier")
const expire = 30
const otpCode = getOtpCode("secret", expire)
const result = checkCodeFromClient("secret", "string or number code")
```