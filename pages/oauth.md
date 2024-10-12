---
title: "OAuth"
---

# OAuth

## 목차

- [개요](#개요)
- [Create authorization URL](#create-authorization-url)
- [Validate authorization code](#validate-authorization-code)
- [Proof key for code exchange (PKCE)](#proof-key-for-code-exchange-pkce-flow)
- [OpenID Connect (OIDC)](#openid-connect-oidc)
	- [OpenID Connect Discovery](#openid-connect-discovery)
- [Account linking](#account-linking)
- [Other considerations](#other-considerations)

## 개요

OAuth는 널리 사용되는 인증 프로토콜입니다. "구글로 로그인", "GitHub로 로그인" 기능이 OAuth를 기반으로 하고 있습니다. OAuth를 사용하면 사용자가 구글과 같은 외부 서비스에 자신의 자격 증명을 공유하지 않고 애플리케이션에 자원에 대한 접근 권한을 부여할 수 있습니다. 비밀번호 기반 인증을 구현하는 대신, OAuth를 사용하여 서드파티 서비스가 인증을 처리하게 할 수 있습니다. 그 후 사용자의 프로필을 가져와 사용자를 생성하고 세션을 관리할 수 있습니다.

기본적인 OAuth 흐름에서는 사용자가 서드파티 서비스로 리디렉션되고, 서비스가 사용자를 인증한 후 다시 애플리케이션으로 리디렉션됩니다. 이 과정에서 사용자를 대신해 자원에 접근할 수 있는 액세스 토큰이 발급됩니다.

애플리케이션에서는 두 가지 서버 엔드포인트가 필요합니다:

1. 로그인 엔드포인트 (GET): 사용자를 OAuth 제공자로 리디렉션합니다.
2. 콜백 엔드포인트 (GET): OAuth 제공자로부터의 리디렉션을 처리합니다.

OAuth에는 여러 버전이 있지만, 이 문서에서는 OAuth 2.0과 그중에서도 [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)에 표준화된 인증 코드 방식만 다룹니다. 암시적 승인 방식은 사용되지 말아야 하며, 더 이상 사용하지 않는 방식입니다.

## Create authorization URL

GitHub를 예로 들어, 첫 번째 단계는 사용자를 GitHub로 리디렉션하는 GET 엔드포인트(로그인 엔드포인트)를 생성하는 것입니다. 리디렉션 위치는 인증 URL이며, 몇 가지 매개변수가 포함됩니다.

```
https://github.com/login/oauth/authorize?
response_type=code
&client_id=<CLIENT_ID>
&redirect_uri=<CALLBACK_ENDPOINT>
&state=<STATE>
```

state는 인증 프로세스를 시작한 사용자와 리디렉션된 사용자가 동일한지 확인하기 위해 사용됩니다. 따라서 요청마다 새로운 state를 생성해야 합니다. 명시적으로 요구되는 것은 아니지만 권장되며, 제공자에 따라 필수일 수도 있습니다. state는 암호적으로 안전한 난수 생성기를 사용해 최소 112비트 이상의 엔트로피로 생성해야 합니다. 또한, 로그인 엔드포인트에서 콜백 엔드포인트로 데이터를 전달하는 데 사용할 수도 있지만, 쿠키를 사용하는 것이 더 간편할 수 있습니다.

서버는 각 시도와 관련된 `state`를 추적해야 합니다. 간단한 방법으로는 `HttpOnly`, `SameSite=Lax`, `Secure`, `Path=/` 속성이 있는 쿠키로 저장하는 방법이 있습니다. 또는 `state`를 현재 세션에 할당할 수도 있습니다.

추가 자원에 접근하기 위해 `scope` 매개변수를 정의할 수 있습니다. 여러 `scope`가 있을 경우, 공백으로 구분해야 합니다.

```
&scope=email%20identity
```

로그인 엔드포인트에 링크를 추가하여 "로그인" 버튼을 만들 수 있습니다.

```html
<a href="/login/github">Sign in with GitHub</a>
```

## Validate authorization code

사용자는 인증 코드가 포함된 상태로(쿼리 매개변수로 포함됨) 콜백 엔드포인트(즉, `redirect_uri`에 정의된 위치)로 리디렉션됩니다. 이 코드는 액세스 토큰으로 교환됩니다.

```
https://example.com/login/github/callback?code=<CODE>&state=<STATE>
```

`state`를 인증 URL에 추가하면 리디렉션 요청에 state 매개변수가 포함됩니다. 이 `state`가 시도와 일치하는지 확인하는 것이 중요합니다. state가 없거나 일치하지 않으면 오류를 반환해야 합니다. state 매개변수를 확인하지 않는 것은 흔한 실수입니다.

코드는 OAuth 제공자의 토큰 엔드포인트로 `application/x-www-form-urlencoded` `POST` 요청을 통해 전송됩니다.

```
POST https://github.com/login/oauth/access_token
Accept: application/json
Authorization: Basic <CREDENTIALS>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=<CLIENT_ID>
&redirect_uri=<CALLBACK_ENDPOINT>
&code=<CODE>
```

OAuth 제공자가 클라이언트 비밀을 사용하는 경우, 클라이언트 ID와 비밀을 포함한 기본 인증 헤더에서 base64로 인코딩되어야 합니다.

```go
var clientId, clientSecret string
credentials := base64.StdEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
```

일부 제공자는 클라이언트 비밀을 본문에 포함시키는 것도 허용합니다.

```
POST https://github.com/login/oauth/access_token
Accept: application/json
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
&redirect_uri=<CALLBACK_ENDPOINT>
&code=<CODE>
```

이 요청은 액세스 토큰을 반환하며, 이 토큰을 사용해 사용자의 신원을 확인할 수 있습니다. 추가로 `refresh_token`이나 `expires_in` 같은 필드도 포함될 수 있습니다.

```
{ "access_token": "<ACCESS_TOKEN>" }
```

예를 들어, 액세스 토큰을 사용하여 사용자의 GitHub 프로필을 가져오고 GitHub 사용자 ID를 저장할 수 있습니다. 이를 통해 사용자가 다시 로그인할 때 등록된 계정을 찾을 수 있습니다. OAuth 제공자가 제공하는 이메일 주소가 인증되지 않았을 수 있다는 점을 유의하세요. 이메일을 수동으로 인증하거나 인증되지 않은 사용자의 경우 로그인 절차를 차단해야 할 수 있습니다.

액세스 토큰 자체는 세션 대체 수단으로 사용되어서는 안 됩니다.

## Proof key for code exchange (PKCE) flow

PKCE는 OAuth 2.0에 추가 보호를 제공하기 위해 [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
에서 도입되었습니다. 제공자가 지원하는 경우, 상태 및 클라이언트 비밀과 함께 사용하는 것이 좋습니다. 일부 OAuth 제공자는 PKCE가 활성화된 경우 클라이언트 비밀이 필요하지 않으므로, 이 경우 PKCE는 사용하지 않아야 합니다.

PKCE는 상태를 완전히 대체할 수 있으며, 둘 다 CSRF 공격을 방지하지만 OAuth 제공자가 요구할 수 있습니다.

각 요청에서 새로운 코드 검증자를 생성해야 하며, 최소 112비트 이상의 엔트로피로 암호적으로 안전한 난수 생성기를 사용하여 생성해야 합니다(RFC에서는 256비트를 권장). 상태와 유사하게, 애플리케이션은 각 시도와 관련된 코드 검증자를 추적해야 합니다(쿠키나 세션 사용). base64url로 인코딩된 SHA256 해시(패딩 없음)를 코드 챌린지로 변환하여 인증 URL에 포함시킵니다.

```go
var codeVerifier string
codeChallengeBuf := sha256.Sum256([]byte(codeVerifier))
codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(codeChallengeBuf)
```

```
https://accounts.google.com/o/oauth2/v2/auth?
response_type=code
&client_id=<...>
&redirect_uri=<...>
&state=<...>
&code_challenge_method=S256
&code_challenge=<CODE_CHALLENGE>
```

콜백 엔드포인트에서 현재 시도와 관련된 코드 검증자를 인증 코드와 함께 전송해야 합니다.

```
POST https://oauth2.googleapis.com/token
Accept: application/json
Authorization: Basic <CREDENTIALS>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=<...>
&redirect_uri=<...>
&code=<...>
&code_verifier=<CODE_VERIFIER>
```

## OpenID Connect (OIDC)

[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html)는 OAuth 2.0 위에 구축된 널리 사용되는 프로토콜입니다. OAuth에 중요한 추가 사항은 인증 제공자가 액세스 토큰과 함께 ID 토큰을 반환한다는 점입니다. ID 토큰은 사용자 데이터를 포함하는 [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)입니다. sub 필드에 사용자의 고유 식별자를 항상 포함합니다.

```
{
	"access_token": "<ACCESS_TOKEN>",
	"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiZXhhbXBsZS5jb20ifQ.uMMQPfp7LwcLiBbfZdoHdIPjKgS2HUfOr5vlY71el8A"
}
```

토큰을 공개 키로 검증할 수 있지만, HTTPS를 사용해 통신 중이라면 서버 측 애플리케이션에서 반드시 필요한 것은 아닙니다.

### OpenID Connect Discovery

OpenID Connect는 OAuth 2.0 엔드포인트 위치를 동적으로 가져올 수 있는 [디스커버리 메커니즘](https://openid.net/specs/openid-connect-discovery-1_0.html)을 정의합니다. 이를 통해 애플리케이션에서 엔드포인트 URL을 하드코딩할 필요가 없습니다. OpenID Connect Discovery를 사용하려면 OpenID 제공자가 디스커버리 엔드포인트를 제공해야 합니다.

디스커버리 엔드포인트는 OpenID 제공자의 구성 정보를 포함하는 JSON 문서를 반환하는 잘 알려진 URL입니다. 모든 OAuth 제공자가 OpenID Connect Discovery를 지원하는 것은 아닙니다. 제공자의 문서를 확인하여 디스커버리 엔드포인트가 있는지 확인하세요. 그렇지 않은 경우, 애플리케이션에서 엔드포인트 URL을 수동으로 구성해야 할 수 있습니다.

잘 알려진 URL 경로는 `/.well-known/openid-configuration`입니다. 예를 들어, 구글의 디스커버리 엔드포인트는 다음과 같습니다:

```
https://accounts.google.com/.well-known/openid-configuration
```

이 엔드포인트는 OpenID 제공자의 구성 정보를 포함하는 JSON 객체를 반환하며, 여기에는 인증, 토큰 교환, 사용자 정보 검색을 위한 엔드포인트 URL이 포함됩니다.

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "code_challenge_methods_supported": ["S256"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": ["openid", "email", "profile"]
}
```

OpenID Connect Discovery를 사용하면 애플리케이션이 OpenID 제공자의 구성 변경 사항에 동적으로 적응할 수 있으며, 코드 업데이트가 필요하지 않습니다. 이를 통해 항상 최신 엔드포인트 URL을 사용할 수 있습니다. 다만, 추가로 fetch 요청을 해야 하는 단점이 있습니다.

## Account linking

계정 연결을 통해 사용자는 여러 소셜 계정으로 로그인하고 애플리케이션에서 동일한 사용자로 인증될 수 있습니다. 주로 제공자와 등록된 이메일 주소를 확인하여 이루어집니다. 이메일을 사용해 계정을 연결하는 경우, 사용자의 이메일을 검증해야 합니다. 대부분의 제공자는 사용자 프로필에 `is_verified` 필드나 유사한 항목을 제공합니다. 제공자의 문서에 명시되지 않는 한, 이메일이 검증되었음을 가정하지 마세요. 검증되지 않은 이메일을 가진 사용자는 인증 절차를 완료할 수 없도록 차단하고 이메일을 먼저 검증하도록 유도해야 합니다.

## Other considerations

- [Open redirect](/open-redirect).
