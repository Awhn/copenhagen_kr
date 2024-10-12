---
title: "WebAuthn"
---

# WebAuthn

## Table of contents

-   [Overview](#overview)
-   [Vocabulary](#vocabulary)
-   [Registration](#registration)
-   [Authentication](#authentication)

## Overview

[Web Authentication (WebAuthn) 표준](https://www.w3.org/TR/webauthn-2/)은 사용자가 PIN 코드나 생체 인식을 통해 기기로 인증할 수 있도록 합니다. 개인 키는 사용자의 기기에 저장되고, 공개 키는 애플리케이션에 저장됩니다. 애플리케이션은 서명을 검증하여 사용자를 인증할 수 있습니다. 자격 증명은 사용자의 기기(또는 여러 기기)에 종속되며, 무차별 대입 공격이 불가능하기 때문에 공격자가 기기에 물리적으로 접근해야만 공격이 가능합니다.

WebAuthn은 보통 두 가지 방식으로 사용됩니다: 패스키(passkey)와 보안 토큰(security token). 엄격한 정의는 없지만, 패스키는 비밀번호를 대체할 수 있는 자격 증명으로 인증기(resident key)에 저장됩니다. 반면 보안 토큰은 비밀번호로 인증한 후 사용되는 2차 요소로 사용됩니다. 2차 인증을 위한 자격 증명은 보통 암호화되어 신뢰하는 서버에 저장됩니다. 두 경우 모두 기존 방식보다 더 안전한 대안입니다.

WebAuthn을 사용하여 애플리케이션은 기기를 제조사와 함께 검증할 수 있지만, 이 과정은 여기서 다루지 않습니다.

## Vocabulary

-   신뢰 당사자: 귀하의 애플리케이션.
-   인증기: 자격 증명을 보유한 기기.
-   챌린지: 재사용을 방지하기 위해 생성된 랜덤한 단회용 [토큰](/server-side-tokens). 최소 16바이트의 엔트로피를 권장합니다.
-   사용자 접근 확인: 사용자가 기기에 접근할 수 있는 상태.
-   사용자 인증: 사용자가 PIN 코드나 생체 인식을 통해 자신의 신원을 확인한 상태.
-   Resident key, 발견 가능한 자격 증명: 인증기(사용자 기기나 보안 토큰)에 저장된 자격 증명. 비거주 키(non-resident key)는 신뢰 당사자의 서버(데이터베이스)에 암호화되어 저장됩니다.

## Registration

등록 단계에서는 인증기가 새로운 자격 증명을 생성하고 그 공개 키를 반환합니다.

클라이언트에서는 서버로부터 새로운 챌린지를 받아 [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)를 사용하여 새로운 자격 증명을 생성합니다. 이 과정에서 사용자는 기기를 통해 인증해야 합니다. Safari와 같은 브라우저는 사용자의 상호작용(버튼 클릭 등) 없이 이 메서드를 호출할 수 없습니다.

```ts
const credential = await navigator.credentials.create({
	publicKey: {
		attestation: "none",
		rp: { name: "My app" },
		user: {
			id: crypto.getRandomValues(new Uint8Array(32)),
			name: username,
			displayName: name,
		},
		pubKeyCredParams: [
			{
				type: "public-key",
				// ECDSA with SHA-256
				alg: -7,
			},
		],
		challenge,
		authenticatorSelection: {
			// See note below.
			userVerification: "required",
			residentKey: "required",
			requireResidentKey: true,
		},
		// list of existing credentials
		excludeCredentials: [
			{
				id: new Uint8Array(/*...*/),
				type: "public-key",
			},
		],
	},
});
if (!(credential instanceof PublicKeyCredential)) {
	throw new Error("Failed to create credential");
}
const response = credential.response;
if (!(response instanceof AuthenticatorAttestationResponse)) {
	throw new Error("Unexpected");
}

const clientDataJSON: ArrayBuffer = response.clientDataJSON;
const attestationObject: ArrayBuffer = response.attestationObject;
```

-   `rp.name`: 귀하의 애플리케이션 이름.
-   `user.id`: 인증기를 위한 랜덤 사용자 ID. 애플리케이션에서 사용하는 실제 사용자 ID와 다를 수 있습니다.
-   `user.name`: 사람이 읽기 쉬운 사용자 식별자(사용자 이름, 이메일 등).
-   `user.displayName`: 사람이 읽기 쉬운 표시 이름(고유할 필요는 없음).
-   `excludeCredentials`: 중복 자격 증명을 방지하기 위한 사용자의 자격 증명 목록.

알고리즘 ID는 [IANA COSE 알고리즘 레지스트리](https://www.iana.org/assignments/cose/cose.xhtml)에서 가져옵니다. ECDSA with SHA-256 (ES256)이 널리 지원되므로 추천됩니다. 더 넓은 범위의 기기를 지원하기 위해 `-257`을 사용하여 RSASSA-PKCS1-v1.5 (RS256)를 사용할 수도 있지만, 이를 지원하는 기기는 드뭅니다.

대부분의 경우 `attestation`은 `"none"`으로 설정하는 것이 좋습니다. 인증기를 확인할 필요가 없으며, 모든 인증기가 이를 지원하지는 않습니다.

패스키를 사용하는 경우 공개 키가 resident key이고 사용자 인증이 필요함을 확인하세요.

```ts
const credential = await navigator.credentials.create({
	publicKey: {
		// ...
		authenticatorSelection: {
			userVerification: "required",
			residentKey: "required",
			requireResidentKey: true,
		},
	},
});
```

보안 토큰을 사용할 때는 사용자 인증을 생략할 수 있으며, 자격 증명이 `resident key`일 필요는 없습니다. `authenticatorAttachment`를 `cross-platform`으로 설정하여 인증기를 보안 토큰으로 제한할 수도 있습니다.

```ts
const credential = await navigator.credentials.create({
	publicKey: {
		// ...
		authenticatorSelection: {
			userVerification: "discouraged",
			residentKey: "discouraged",
			requireResidentKey: false,
			authenticatorAttachment: "cross-platform",
		},
	},
});
```

클라이언트 데이터 JSON과 인증기 데이터를 서버로 전송하여 검증합니다. 이진 데이터를 전송하는 간단한 방법은 base64로 인코딩하는 것입니다. 다른 방법으로는 CBOR와 같은 스키마를 사용하여 JSON 유사 데이터를 이진으로 인코딩할 수도 있습니다.

첫 번째 단계는 CBOR로 인코딩된 attestation 객체를 파싱하는 것입니다. 여기에는 attestation 문과 인증기 데이터가 포함됩니다. 사용자의 기기를 확인하기 위해 attestation 문을 사용할 수 있습니다. 클라이언트에서 이를 `"none"`으로 설정한 경우, 문서 형식이 `none`인지 확인하십시오.

```go
var attestationObject AttestationObject

// Parse attestation object

if attestationObject.Fmt != "none" {
	return errors.New("invalid attestation statement format")
}

type AttestationObject  struct {
	Fmt                  string // "fmt"
	AttestationStatement AttestationStatement // "attStmt"
	AuthenticatorData    []byte // "authData"
}

type AttestationStatement struct {
	// see spec
}
```

다음은 인증기 데이터를 파싱하는 단계입니다.

-   바이트 0-31: 신뢰 당사자 ID 해시.
-   바이트 32: 플래그:
    -   비트 0 (가장 오른쪽): 사용자 접근 확인.
    -   비트 2: 사용자 인증 확인.
    -   비트 6: 자격 증명 데이터 포함 여부.
-   바이트 33-36: 서명 카운터.
-   가변 바이트: 자격 증명 데이터(이진).

신뢰 당사자 ID는 프로토콜이나 포트 없이 도메인입니다. 인증기 데이터에는 이 도메인의 SHA-256 해시가 포함됩니다. `localhost`의 경우 신뢰 당사자 ID는 `localhost`입니다. 사용자 접근 확인 플래그를 확인하고 사용자 인증이 필요한 경우 사용자 인증 플래그도 확인하십시오. 서명 카운터는 자격 증명이 사용될 때마다 증가하며, 위조된 기기를 감지하는 데 사용할 수 있습니다. 자격 증명이 토큰에 종속된 하드웨어 보안 토큰에서 사용될 경우, 카운터를 저장하고 이전 시도보다 큰지 확인해야 합니다. 그러나 패스키는 여러 기기에서 공유할 수 있으므로 이를 무시해도 됩니다.

그다음, 자격 증명 ID와 공개 키를 자격 증명 데이터에서 추출합니다.

-   바이트 0-15: 인증기 ID.
-   바이트 16-17: 자격 증명 ID 길이.
-   가변 바이트: 자격 증명 ID.
-   가변 바이트: COSE 공개 키.

공개 키는 CBOR로 인코딩된 COSE 키입니다.

```go
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
)
if len(authenticatorData) < 37 {
	return errors.New("invalid authenticator data")
}
rpIdHash := authenticatorData[0:32]
expectedRpIdHash := sha256.Sum256([]byte("example.com"))
if bytes.Equal(rpIdHash, expectedRpIdHash[:]) {
	return errors.New("invalid relying party ID")
}

// Check for the "user present" flag.
if (authenticatorData[32] & 1) != 1 {
	return errors.New("user not present")
}
// Check for the "user verified" flag if you need user verification.
if ((authenticatorData[32] >> 2) & 1) != 1 {
	return errors.New("user not verified")
}
if ((authenticatorData[32] >> 6) & 1) != 1 {
	return errors.New("missing credentials")
}

if (len(authenticatorData) < 55) {
	return errors.New("invalid authenticator data")
}
credentialIdSize:= binary.BigEndian.Uint16(authenticatorData[53 : 55])
if (len(authenticatorData) < 55 + credentialIdSize) {
	return errors.New("invalid authenticator data")
}
credentialId := authenticatorData[55 : 55+credentialIdSize]
coseKey := authenticatorData[55+credentialIdSize:]

// Parse COSE public key
```

공개 키의 구조는 사용된 알고리즘에 따라 달라집니다. 아래는 ECDSA의 공개 키로, 이는 공개 키로 (x, y)를 사용합니다. 알고리즘과 곡선을 검증합니다.

```
{
	1: 2 // EC2 key type
	3: -7 // Algorithm ID for ECDSA P-256 with SHA-256
	-1: 1 // Curve ID for P-256
	-2: 0x00...00 // x coordinate in bit string
	-3: 0x00...00 // y coordinate in bit string
}
```

다음으로, JSON으로 인코딩된 클라이언트 데이터를 검증합니다. 원본은 프로토콜과 포트가 포함된 애플리케이션의 도메인입니다. 클라이언트 데이터의 챌린지는 패딩 없는 base64url로 인코딩됩니다.

```go
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

var expectedChallenge []byte

// Verify the challenge and delete it from storage.

var credentialId string

var clientData ClientData

// Parse JSON

if clientData.Type != "webauthn.create" {
	return errors.New("invalid type")
}
if !verifyChallenge(clientData.Challenge) {
	return errors.New("invalid challenge")
}
if clientData.Origin != "https://example.com" {
	return errors.New("invalid origin")
}

type ClientData struct {
	Type	  string // "type"
	Challenge string // "challenge"
	Origin	  string // "origin"
}
```

마지막으로, 공개 키와 자격 증명 ID를 사용하여 새 사용자를 생성합니다. COSE로 인코딩된 공개 키를 더 작고 표준화된 형식(([ECDSA](/cryptography/ecdsa#public-keys)))으로 변환할 것을 권장합니다.

## Authentication

인증 단계에서는 인증기가 개인 키를 사용해 새로운 서명을 생성합니다.

서버에서 챌린지를 생성하고 사용자를 인증합니다.

```ts
const credential = await navigator.credentials.get({
	publicKey: {
		challenge,
		userVerification: "required",
	},
});

if (!(credential instanceof PublicKeyCredential)) {
	throw new Error("Failed to create credential");
}
const response = credential.response;
if (!(response instanceof AuthenticatorAssertionResponse)) {
	throw new Error("Unexpected");
}

const clientDataJSON: ArrayBuffer = response.clientDataJSON);
const authenticatorData: ArrayBuffer = response.authenticatorData
const signature: ArrayBuffer = response.signature);
const credentialId: ArrayBuffer = publicKeyCredential.rawId;
```

보안 토큰으로 2차 인증을 구현하려면, `allowCredentials`에 사용자의 자격 증명 목록을 전달하여 비거주 키를 지원해야 합니다.

```ts
const credential = await navigator.credentials.get({
	publicKey: {
		challenge,
		userVerification: "required",
		// list of user credentials
		allowCredentials: [
			{
				id: new Uint8Array(/*...*/),
				type: "public-key",
			},
		],
	},
});
```

클라이언트 데이터, 인증기 데이터, 서명, 자격 증명 ID가 서버로 전송됩니다. 챌린지, 인증기, 클라이언트 데이터를 먼저 검증합니다. 이 부분은 클라이언트 데이터 유형이 `webauthn.get`이어야 한다는 점을 제외하고는 attestation을 검증하는 단계와 거의 동일합니다.

```go
if clientData.Type != "webauthn.get" {
	return errors.New("invalid type")
}
```

또한, 인증기의 자격 증명 부분은 포함되지 않습니다.

자격 증명 ID를 사용하여 자격 증명의 공개 키를 가져옵니다. *2차 인증에서는 자격 증명이 인증된 사용자에게 속하는지 확인해야 합니다.* 이 검사를 생략하면 악의적인 행위자가 2차 인증을 완전히 건너뛸 수 있습니다. 서명은 인증기 데이터와 클라이언트 데이터 JSON의 SHA-256 해시입니다. ECDSA의 경우, 서명은 [ASN.1 DER](/cryptography/ecdsa#pkix) 인코딩입니다

```go
import (
	"crypto/ecdsa"
	"crypto/sha256"
)

clientDataJSONHash := sha256.Sum256(clientDataJSON)
// Concatenate the authenticator data with the hashed client data JSON.
data := append(authenticatorData, clientDataJSONHash[:]...)
hash := sha256.Sum256(data)
validSignature := ecdsa.VerifyASN1(publicKey, hash[:], signature)
```
