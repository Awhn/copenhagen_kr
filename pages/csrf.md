---
title: "Cross-site request forgery (CSRF)"
---

# Cross-site request forgery (CSRF)

## 목차

- [개요](#개요)
	- [Cross-site vs cross-origin](#cross-site-vs-cross-origin)
- [예방](#예방)
	- [Anti-CSRF tokens](#anti-csrf-tokens)
	- [Signed double-submit cookies](#signed-double-submit-cookies)
	- [Origin header](#origin-header)
- [SameSite cookie attribute](#samesite-cookie-attribute)

## 개요

CSRF 공격은 자격 증명이 쿠키에 저장되어 있을 때 공격자가 사용자를 대신하여 인증 요청을 할 수 있도록 합니다.

클라이언트가 교차 출처 요청을 하면 브라우저는 요청이 허용되는지 여부를 확인하기 위해 사전 요청(CORS)을 보냅니다. 그러나 양식 제출 등 특정 '단순' 요청의 경우 이 단계는 생략됩니다. 또한 출처가 다른 요청에도 쿠키가 자동으로 포함되므로 악의적인 공격자가 도메인에서 토큰을 직접 훔치지 않고도 인증된 사용자로 요청을 할 수 있습니다. [동일 출처 정책](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)은 기본적으로 교차 출처 클라이언트가 응답을 읽는 것을 금지하지만 요청은 여전히 진행됩니다.

예를 들어, `bank.com`에 로그인한 경우 양식이 다른 도메인에서 호스팅되는 경우에도 세션 쿠키가 이 양식 제출과 함께 전송됩니다.

```html
<form action="https://bank.com/send-money" method="post">
	<input name="recipient" value="attacker" />
	<input name="value" value="$100" />
	<button>Send money</button>
</form>
```

이것은 `fetch()` 요청일 수 있으므로 사용자 입력이 필요하지 않습니다.

```ts
const body = new URLSearchParams();
body.set("recipient", "attacker");
body.set("value", "$100");

await fetch("https://bank.com/send-money", {
	method: "POST",
	body
});
```

### Cross-site vs cross-origin

완전히 다른 두 도메인 간의 요청은 교차 사이트 및 교차 출처로 간주되지만, 두 하위 도메인 간의 요청은 교차 사이트로 간주되지 않지만 교차 출처 요청으로 간주됩니다. 크로스 사이트 요청 위조라는 이름은 크로스 사이트 요청을 의미하지만, 기본적으로 크로스 오리진 공격으로부터 애플리케이션을 엄격하게 보호해야 합니다.

## 예방

CSRF는 신뢰할 수 있는 출처의 브라우저에서 발생한 POST 및 POST와 유사한 요청만 허용함으로써 방지할 수 있습니다.

양식을 처리하는 모든 경로에 대해 보호 기능을 구현해야 합니다. 현재 애플리케이션에서 양식을 사용하지 않는 경우에도 향후 문제를 방지하기 위해 최소한 [`오리진` 헤더](#origin-header)를 확인하는 것이 좋습니다. 또한 일반적으로 리소스는 POST 및 POST와 유사한 메서드(PUT, DELETE 등)만 사용하여 수정하는 것이 좋습니다.

일반적인 토큰 기반 접근 방식의 경우, 토큰은 뒤로 버튼 하나만 누르면 깨지기 때문에 일회용(예: 양식 제출 시마다 새 토큰을 사용)이 아니어야 합니다. 또한 페이지에 엄격한 CORS(교차 출처 리소스 공유) 정책을 적용하는 것이 중요합니다. 액세스 제어 허용 자격 증명`이 엄격하지 않으면 악성 사이트가 유효한 CSRF 토큰이 포함된 HTML 양식을 얻기 위해 GET 요청을 보낼 수 있습니다.

### Anti-CSRF tokens

이것은 각 세션에 고유한 CSRF [토큰](/server-side-tokens)이 연결된 매우 간단한 방법입니다.

```html
<form method="post">
	<input name="message" />
	<input type="hidden" name="__csrf" value="<CSRF_TOKEN>" />
	<button>Submit</button>
</form>
```

### Signed double-submit cookies

토큰을 서버 측에 저장할 수 없는 경우 서명된 이중 제출 쿠키를 사용하는 것도 한 가지 방법입니다. 이는 양식에 포함된 토큰이 비밀로 서명된다는 점에서 기본 이중 제출 쿠키와 다릅니다.

새로운 [토큰](/server-side-tokens)이 생성되고 비밀 키를 사용하여 HMAC SHA-256으로 해시됩니다.

```go
func generateCSRFToken() (string, []byte) {
	buffer := [10]byte{}
	crypto.rand.Read(buffer)
	csrfToken := base64.StdEncoding.encodeToString(buffer)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(csrfToken))
	csrfTokenHMAC := mac.Sum(nil)
	return csrfToken, csrfTokenHMAC
}

// 선택적으로 쿠키를 특정 세션 ID에 연결합니다.
func generateCSRFToken(sessionId string) (string, []byte) {
	// ...
	mac.Write([]byte(csrfToken + "." + sessionId))
	csrfTokenHMAC := mac.Sum(nil)
	return csrfToken, csrfTokenHMAC
}
```

토큰은 쿠키로 저장되고 HMAC은 형식으로 저장됩니다. 쿠키에는 `Secure`, `HttpOnly`, `SameSite` 플래그가 있어야 합니다. 요청의 유효성을 검사하기 위해 쿠키는 양식 데이터에 전송된 서명을 확인하는 데 사용될 수 있습니다.

#### Traditional double-submit cookies

서명되지 않은 일반 이중 제출 쿠키는 공격자가 애플리케이션 도메인의 하위 도메인에 액세스할 수 있는 경우 여전히 취약한 상태로 남습니다. 이렇게 하면 공격자가 자체적으로 이중 제출 쿠키를 설정할 수 있습니다.

### Origin header

CSRF 공격을 방지하는 매우 간단한 방법은 비-GET 요청에 대해 요청의 `Origin` 헤더를 확인하는 것입니다. [origin](https://developer.mozilla.org/en-US/docs/Glossary/Origin) 요청을 포함하는 상대적으로 새로운 헤더입니다. 만약 이 헤더에 의존하고 있다면, 어플리케이션이 자원 수정을 위해 GET 요청을 사용하지 않아야 합니다.

사용자 정의 클라이언트를 사용하면 `Origin` 헤더를 스푸핑할 수 있지만, 중요한 부분은 클라이언트 측 자바스크립트를 사용하면 스푸핑할 수 없다는 것입니다. 사용자는 브라우저를 사용할 때만 CSRF에 취약합니다.

```go
func handleRequest(w http.ResponseWriter, request *http.Request) {
  	if request.Method != "GET" {
		originHeader := request.Header.Get()
		// You can also compare it against the Host or X-Forwarded-Host header.
		if originHeader != "https://example.com" {
			// Invalid request origin
			w.WriteHeader(403)
			return
		}
  	}
  	// ...
}
```

2020년경부터 모든 최신 브라우저에서 `Origin` 헤더를 지원하지만, 그 이전에도 Chrome과 Safari에서 지원했습니다. `Origin` 헤더가 포함되지 않은 경우 요청을 허용하지 마세요.

`Referer` 헤더는 `Origin` 헤더 이전에 도입된 유사한 헤더입니다. 이 헤더는 `Origin` 헤더가 정의되지 않은 경우 폴백으로 사용할 수 있습니다.

## SameSite cookie attribute

세션 쿠키에는 `SameSite` 플래그가 있어야 합니다. 이 플래그는 브라우저가 요청에 쿠키를 포함하는 시기를 결정합니다. 사이트 간 요청이 [안전한 HTTP 메서드](https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP)(예: GET)를 사용하는 경우에만 `SameSite=Lax` 쿠키가 전송되며, `SameSite=Strict` 쿠키는 모든 사이트 간 요청에 전송되지 않습니다. 사용자가 외부 링크를 통해 웹사이트에 액세스할 때 `Strict` 쿠키가 전송되지 않으므로 기본값으로 `Lax`를 사용하는 것이 좋습니다.

값을 `Lax`로 설정하면 애플리케이션에서 리소스 수정을 위한 GET 요청을 사용하지 않는 것이 중요합니다. 동일 사이트` 플래그에 대한 브라우저 지원은 현재 96%의 웹 사용자가 사용할 수 있음을 보여줍니다. 이 플래그는 *사이트 간* 요청 위조(*출처 간* 요청 위조가 아님)에 대해서만 보호하며 일반적으로 유일한 방어 계층이 되어서는 안 된다는 점에 유의해야 합니다.

