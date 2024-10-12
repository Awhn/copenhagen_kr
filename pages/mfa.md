---
title: "Multi-factor authentication (MFA)"
---

# Multi-factor authentication (MFA)

## 목차

- [개요](#개요)
- [Time-based one-time passwords (TOTP)](#time-based-one-time-passwords-totp)
	- [Generate QR code](#generate-qr-code)
	- [Validate OTPs](#validate-otps)
- [SMS](#sms)
- [WebAuthn](#webauthn)
- [Recovery codes](#recovery-codes)

## 개요

MFA는 사용자가 인증을 위해 비밀번호 이상의 정보를 입력해야 하는 경우입니다. 크게 5가지 유형이 있습니다:

- 알고 있는 정보: 비밀번호
- 가지고 있는 것: 장치, 이메일 주소, SMS
- 사용자 정보 생체 인식
- 현재 위치
- 당신이 하는 일

## Time-based one-time passwords (TOTP)

TOTP는 [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)에 정의되어 있으며, [RFC 4226](https://www.ietf.org/rfc/rfc4226.txt)에 정의된 해시 기반 일회용 비밀번호(HOTP)를 기반으로 합니다.

표준 TOTP는 일반적으로 사용자의 모바일 디바이스에 설치된 인증 앱을 사용하여 사용자를 위한 코드를 생성합니다.

각 사용자에게는 비밀 키가 있습니다. 이 비밀 키는 QR 코드를 통해 사용자의 인증 앱과 공유됩니다. 인증 앱은 이 비밀 키와 현재 시간을 사용하여 새 OTP를 생성할 수 있습니다. 앱은 현재 OTP를 요청하고 동일한 매개변수를 사용하여 생성하여 유효성을 검사할 수 있습니다. 현재 시간이 코드를 생성하는 데 사용되므로 각 코드는 설정된 기간(일반적으로 30초) 동안만 유효합니다.

### Generate QR code

TOTP를 생성하는 데는 HMAC SHA-1이 사용됩니다. 비밀 키는 정확히 160비트이며, 암호학적으로 안전한 무작위 생성기를 사용하여 생성해야 합니다. 각 사용자는 고유한 비밀을 가지고 있어야 하며, 비밀은 서버에 저장되어야 합니다. 실수로 데이터베이스 기록이 유출될까 걱정된다면 저장하기 전에 비밀번호를 암호화할 수 있습니다. 하지만 데이터를 암호화한다고 해서 서버에 시스템 수준의 액세스 권한을 가진 공격자로부터 보호할 수 있는 것은 아니라는 점을 기억하세요.

비밀을 공유하려면 [키 URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)를 생성하고 이를 QR 코드로 인코딩하세요. '비밀'은 base32로 인코딩됩니다.

생성된 OTP를 요청하여 사용자가 QR 코드를 올바르게 스캔했는지 확인해야 합니다.

```
otpauth://totp/example%20app:John%20Doe?secret=JBSWY3DPEHPK3PXP&issuer=Example%20App&digits=6&period=30
```

사용자가 새 QR 코드를 요청하면 새 비밀번호를 생성하고 이전 비밀번호를 무효화합니다.

### Validate OTPs

TOTP의 유효성을 검사하려면 먼저 TOTP를 생성해야 합니다.

HOTP는 HMAC으로 카운터 값에 서명하여 생성됩니다. HOTP에서 카운터는 새 코드가 생성될 때마다 증가하는 정수입니다. 그러나 TOTP에서 카운터는 분수 부분이 잘린 현재 UNIX 시간을 간격(보통 30초)으로 나눈 값입니다.

8바이트가 되어야 하는 카운터는 HMAC SHA-1로 해시됩니다. 오프셋을 사용해 4바이트가 추출됩니다. 그런 다음 마지막 31비트를 추출하여 정수로 변환합니다. 마지막으로 마지막 6자리가 OTP로 사용됩니다.

```go
import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
)

func generateTOTP(secret []byte) {
	digits := 6
	counter := time.Now().Unix() / 30

	// HOTP
	mac := hmac.New(sha1.New, secret)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	mac.Write(buf)
	HS := mac.Sum(nil)
	offset := HS[19] & 0x0f
	Snum := binary.BigEndian.Uint32(HS[offset:offset+4]) & 0x7fffffff
	D := Snum % int(math.Pow(10, float64(digits)))
	// Pad "0" to make it 6 digits.
	return fmt.Sprintf("%06d", D)
}
```

OTP의 유효성을 확인하려면 회원님이 직접 생성하고 사용자가 제공한 것과 일치하는지 확인하면 됩니다.

스로틀링을 구현해야 합니다. 기본적인 예로는 5회 연속 실패 후 15분에서 60분 동안 시도를 차단하는 것이 있습니다. 또한 사용자에게 비밀번호를 변경하라는 알림을 보내야 합니다.

## SMS

SMS 기반 MFA는 때때로 가로채고 신뢰할 수 없으므로 권장하지 않습니다. 하지만 인증 앱을 사용하는 것보다 접근성이 더 높을 수 있습니다. 인증 코드 구현에 대한 가이드라인은 [이메일 인증 코드](/email-verification#email-verification-codes) 가이드를 참조하세요. 인증 코드는 약 5분 동안 유효해야 합니다.

스로틀링을 구현해야 합니다. 기본적인 예로는 5회 연속 실패 후 15~60분 동안 시도를 차단하는 것이 있습니다. 또한 사용자에게 비밀번호를 변경하라는 알림을 보내야 합니다.

## WebAuthn

[웹 인증 API(WebAuthn)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)를 사용하면 애플리케이션이 공개 키 암호화를 사용하여 사용자 디바이스를 인증에 사용할 수 있습니다. 디바이스 PIN 코드 또는 생체 인식으로 사용자의 신원을 확인하거나 디바이스만 인증할 수 있습니다. 두 가지 모두 두 번째 요소로 작동하며 후자의 경우 사용자에게 비밀번호/지문을 묻지 않으므로 더 사용자 친화적일 수 있습니다.

구현 방법은 [WebAuthn](/webauthn) 가이드를 참조하세요.

## Recovery codes

애플리케이션에서 MFA를 사용하는 경우 사용자에게 복구 코드를 1개 이상 발급하는 것이 좋습니다. 이는 사용자가 디바이스에 대한 액세스 권한을 잃었을 때 로그인하고 2단계 인증을 재설정하는 데 패스키/OTP 대신 사용할 수 있는 일회용 비밀번호입니다. 이 코드는 암호학적으로 안전한 무작위 생성기를 사용하여 생성해야 합니다. 적절한 스로틀링이 구현되어 있다고 가정하면 40비트(16진수로 인코딩할 경우 10자)의 엔트로피만으로 생성할 수 있습니다. 

이러한 코드를 안전하게 저장할 수 없다면 선호하는 비밀번호 해싱 알고리즘(예: Argon2id)으로 해싱하는 것이 좋습니다. 이 경우 코드는 사용자가 2단계 인증을 처음 등록할 때만 표시됩니다. 또한 사용자에게 2단계 인증서에 액세스할 수 있는 경우 코드를 다시 생성할 수 있는 옵션이 제공되어야 합니다.