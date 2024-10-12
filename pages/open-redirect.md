---
title: "Open redirect"
---

# Open redirect

오픈 리디렉션은 애플리케이션이 사용자가 리디렉션할 위치를 제어할 수 있게 허용하는 취약점을 말합니다.

예를 들어, 사용자가 로그인한 후 원래 페이지로 다시 리디렉션되도록 하고 싶을 수 있습니다. 이를 위해 로그인 페이지와 폼에 `redirect_to URL` 쿼리 매개변수를 추가할 수 있습니다. 사용자가 로그인하면 `redirect_to`에 정의된 위치로 리디렉션됩니다.

```
https://example.com/login?redirect_to=%2Fhome
```

그러나 만약 리디렉션 위치를 검증하지 않고 아무 위치나 허용한다면 어떻게 될까요?

```
https://example.com/login?redirect_to=https%3A%2F%2Fscam.com
```

처음에는 무해해 보일 수 있지만, 이는 사용자를 속이기 쉽게 만듭니다. 사용자는 공격자가 만든 동일한 사이트로 리디렉션될 수 있으며, 다시 비밀번호를 입력하라는 요청을 받을 수 있습니다.