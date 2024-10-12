---
title: "Server-side tokens"
---

# Server-side tokens

## Table of contents

- [Overview](#overview)
- [Generating tokens](#generating-tokens)
- [Storing tokens](#storing-tokens)

## Overview

"서버 사이드 토큰"은 서버에 저장된 임의의 긴 문자열을 말합니다. 이는 데이터베이스나 인메모리 데이터 저장소(예: Redis)에 지속적으로 저장될 수 있으며, 인증 및 검증에 사용됩니다. 토큰은 저장소에 존재하는지를 확인함으로써 검증됩니다. 세션 ID, 이메일 인증 토큰, 접근 토큰 등이 그 예시입니다.

```
CREATE TABLE token (
	token STRING NOT NULL UNIQUE,
	expires_at INTEGER NOT NULL,
	user_id INTEGER NOT NULL,

	FOREIGN KEY (user_id) REFERENCES user(id)
)
```

단일 사용 토큰의 경우, 조회 시 삭제도 보장되어야 합니다. 예를 들어, SQL에서는 트랜잭션과 같은 원자적 연산을 사용해 토큰을 가져와야 합니다.

## Generating tokens

토큰은 최소 112비트의 엔트로피를 가져야 합니다(120-256 비트가 적절한 범위입니다). 예를 들어, 15바이트의 임의 데이터를 생성하고 base32로 인코딩하여 24자 길이의 토큰을 만들 수 있습니다. 하나씩 임의의 문자를 선택하여 토큰을 생성하는 경우, 유사한 수준의 엔트로피를 보장해야 합니다. 자세한 내용은 임의 값 생성 페이지를 참조하십시오.

토큰은 암호적으로 안전한 난수 생성기를 사용하여 생성해야 합니다. 일반적인 수학 패키지에서 제공하는 빠른 의사 난수 생성기는 피하는 것이 좋습니다.

토큰은 대소문자를 구분해야 하지만, 저장소가 대소문자를 구분하지 않는 경우(예: MySQL), 소문자만 사용하는 것도 고려할 수 있습니다.

> 120비트 토큰의 경우, 시스템에 유효한 토큰이 1,000,000개 존재하고 누군가가 초당 10,000개의 토큰을 생성한다고 가정하면, 유효한 토큰을 맞추는 데 2경 년이 걸립니다.

```go
import (
	"crypto/rand"
	"encoding/base32"
)

bytes := make([]byte, 15)
rand.Read(bytes)
sessionId := base32.StdEncoding.EncodeToString(bytes)
```

UUID v4는 이러한 요구 사항에 맞을 수 있지만(122비트의 엔트로피), UUID v4는 공간 효율성이 떨어지며, 스펙상 암호적으로 안전한 난수 생성기를 사용할 것을 보장하지 않습니다.

## Storing tokens

비밀번호 재설정 토큰과 같이 추가적인 보안이 필요한 토큰은 SHA-256으로 해싱되어야 합니다. SHA-256은 토큰이 충분히 길고 임의적이기 때문에 더 느린 알고리즘 대신 사용할 수 있습니다. 토큰은 입력된 토큰을 해싱한 후 쿼리하여 검증할 수 있습니다.

실제 유출 사례로는 [Paleohack](https://www.vpnmentor.com/blog/report-paleohacks-breach/)와 [Spoutible](https://www.troyhunt.com/how-spoutibles-leaky-api-spurted-out-a-deluge-of-personal-data/)가 있습니다.