# Spring Security

### Spring Security란?

스프링 프레임워크를 기반으로 어플리케이션의 **`인증`**과 **`인가`**를 위한 강력한 기능을 제공하는 프레임 워크이다. 
- REST API의 보안을 담당하며, 
- 사용자 인증, 권한 부여 같은 다양한 보안 문제를 처리하는 데 사용된다.

<br>

Spring Security에는 3가지 중요한 개념이 있다.

- **`인증`(Authentication)**
- **`인가`(Authorization)**
- **`서블릿 필터`(Servlet Filter)**


<br><br>

### ❓ 인증이란?

**Authentication**

**인증**은 접근하려는 유저가 누구인지 확인하는 절차입니당. <br>
Spring Security에서는 사용자가 입력한 자격 증명(username, password)을 <br>
시스템에 저장된 자격 증명과 비교해 `인증`을 수행합니다.

<br><br>

### ❓ 인가란?

**Authorization**

**인가**는 사용자가 특정 리소스에 접근할 수 있는 `권한이 있는지를 결정`하는 과정이다.<br>
Spring Security는 사용자에게 할당된 역할(Role)이나 권한(Authority)을 기반으로 인가를 수행한다. <br> 예를 들어, 관리자만 접근할 수 있는 페이지가 있는 경우, Spring Security는 사용자가 관리자 권한을 가지고 있는지를 확인하고 접근을 허용하거나 차단한다.

즉, 
- 로그인이 완료된 사용자인지
- 해당 경로의 접근은 누구에게 열려 있는지
- 해당되는 role을 가지고있는지 말이죠 (admin과 일반 사용자를 구분할 때 좋겠져)

<br><br>

### ❓ 서블릿 필터

Servlet Filter

**서블릿 필터(Servlet Filter)** 는 자바 기반 웹 애플리케이션에서 서블릿에 요청이 도달하기 전이나 응답이 클라이언트로 전송되기 전에 요청과 응답을 가로채고 조작할 수 있는 컴포넌트이다.

```
💡서블릿 필터가 중요한 이유?
서블릿 필터가 Spring MVC 패턴에서 보안 로직을 효과적으로 처리할 수 있는 위치를 제공해주기 때문입니답.

Spring mvc 패턴에서 요청이 들어오면 `dispatcherServlet`이 요청을 받고 알맞은 `controller`로 라우팅 합니다.
이 흐름 사이에 보안 관련된 코드를 넣을곳이 없기 때문이다. 
`dispatcherServlet`은 요청 처리, 뷰 선택, 응답 
생성 등의 MVC 관련 작업에 집중하는 것이 목적이고, `controller`는 실제 요청을 처리하는 부분이기 때문에 
`controller`에 보안관련 코드는 적합하지 않다. 
또한 보안 로직이 각 컨트롤러에 중복될 수 있다. 
그렇기 때문에 서블릿에 요청이 도달하기 전에 보안 로직을 수행할 수 있는 서블릿 필터가 중요한 것이다.
```

<br><br>

### FilterChain

Filter Chain은 클라이언트의 HTTP 요청을 처리하기 위해 구성된 **필터** 집합을 말한다.

![image.png](/Spring/img/springSecurity(1).png)

Spring Security는 인증과 인가를 서블릿 필터를 통해 수행한다. 하지만 서블릿 필터와 Spring Security는 라이프사이클 불일치가 발생한다.

<br><br>

### Servlet Filter와 Spring Security의 불일치
<br>

**Servlet Filter**는 **Servlet Containe**r에 의해 관리가 된다.

- 초기화 : 서블릿 컨테이너가 시작될 때  `web.xml` 에 정의한 필터가 초기화 된다.
- 요청 처리 :  HTTP 요청이 들어올 때마다 서블릿 컨테이너는 요청을 필터 체인을 통해 처리한다.
- 종료 : 서블릿 컨테이너가 종료될 때 필터가 종료된다.

<br>

**Spring Security**는 **ApplicationContext**에 의해 관리가 된다.

- **컨텍스트 초기화** : Spring 애플리케이션이 시작될 때 `ApplicationContext`가 초기화되며, Spring 컨텍스트에 정의된 Bean들이 생성되고 초기화된다.
- **Bean 초기화 및 관리** : `ApplicationContext`는 Bean의 라이프사이클을 관리하며, Bean들이 의존성 주입을 통해 설정된다.
- **컨텍스트 종료 :** 애플리케이션이 종료될 때, `ApplicationContext`는 모든 Bean을 종료하고 자원을 정리한다.

<br>

Servlet Filter 와 Spring Security의 라이프사이클 불일치로 초기화 문제가 발생할 수 있다.
서블릿 필터는 서블릿 컨테이너가 시작될 때 바로 초기화되지만, Spring `ApplicationContext`는 보통 서블릿 컨테이너가 시작된 후 `ContextLoaderListener`나 Spring Boot의 자동 설정에 의해 초기화된다. 즉, 필터가 초기화될 때 `ApplicationContext`가 아직 준비되지 않은 상태일 수 있다.

이러한 문제를 `DelegatingFilterProxy` 로 해결할 수 있다.

<br><br>

### DelegatingFilterProxy

![image.png](/Spring/img/springSecurity(2).png)

`DelegatingFilterProxy`는 서블릿 컨테이너의 필터와 Spring의 `ApplicationContext` 간의 연결 역할을 한다. 서블릿 필터로서 서블릿 컨테이너에 등록되지만 이 필터는 실제 필터 작업을 Spring `ApplicationContext` 내의 특정 Bean에게 위임(delegate)한다. 

`DelegatingFilterProxy`는 지연로딩을 지원하기 때문에 `ApplicationContext` 초기화가 완료된 후에 필터 Bean을 사용한다. 이로 인해 필터 인스턴스를 등록할 때 발생할 수 있는 초기화 문제를 방지할 수 있다.

또한 필터가 Spring `ApplicationContext`에서 관리되므로, Spring의 의존성 주입을 활용할 수 있게 된다.

<br><br>

### FilterChainProxy

`DelegatingFilterProxy`가 특정 Bean에게  위임한다고 했는데 그 특정 필터 Bean이 Spring Security의 `FilterChainProxy` 이다.

![image.png](/Spring/img/springSecurity(3).png)

Spring Security의 **중앙 보안 필터**로, Spring Security의 모든 보안 필터를 관리하고 실행하는 역할을 한다. HTTP 요청이 들어올 때, 요청을 적절한 `SecurityFilterChain`으로 전달하여 각 체인에 정의된 필터들을 실행한다.

<br><br>

### SecurityFilterChain

![image.png](/Spring/img/springSecurity(4).png)

FilterChainProxy가 요청에 맞는 SecurityFilterChain을 선택하면 선택된 SecurityFilterChain 내에 정의된 보안 필터들이 순서대로 실행된다. 만약 요청이 여러 `SecurityFilterChain`에 매칭되더라도, 가장 먼저 매칭된 하나의 `SecurityFilterChain`만 실행된다.


보안 필터는 특정한 순서로 실행된다. 예로 인증을 수행하는 필터는 인가를 수행하는 필터보다 먼저 호출되어야 한다. 

Spring Security를 추가하고 어플리케이션을 실행하면 필터체인의 목록이 보이는데 15개의 필터가 기본 필터들이다. 

```java
2023-06-14T08:55:22.321-03:00  INFO 76975 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Will secure any request with [
org.springframework.security.web.session.DisableEncodeUrlFilter@404db674,
org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@50f097b5,
org.springframework.security.web.context.SecurityContextHolderFilter@6fc6deb7,
org.springframework.security.web.header.HeaderWriterFilter@6f76c2cc,
org.springframework.security.web.csrf.CsrfFilter@c29fe36,
org.springframework.security.web.authentication.logout.LogoutFilter@ef60710,
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@7c2dfa2,
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@4397a639,
org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter@7add838c,
org.springframework.security.web.authentication.www.BasicAuthenticationFilter@5cc9d3d0,
org.springframework.security.web.savedrequest.RequestCacheAwareFilter@7da39774,
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@32b0876c,
org.springframework.security.web.authentication.AnonymousAuthenticationFilter@3662bdff,
org.springframework.security.web.access.ExceptionTranslationFilter@77681ce4,
org.springframework.security.web.access.intercept.AuthorizationFilter@169268a7]
```

<br>

1. **DisableEncodeUrlFilter**: URL 인코딩을 비활성화하여 세션 ID가 URL에 포함되지 않도록 처리
2. **WebAsyncManagerIntegrationFilter**: 비동기 요청의 보안 컨텍스트 통합을 지원
3. **SecurityContextHolderFilter**: `SecurityContext`를 현재 요청 스레드에 설정하고, 요청 완료 후 정리
4. **HeaderWriterFilter**: 응답 헤더에 보안 관련 헤더를 추가
5. **CsrfFilter**: CSRF(Cross-Site Request Forgery) 공격을 방지
6. **LogoutFilter**: 로그아웃 요청을 처리하고 세션을 무효화
7. **UsernamePasswordAuthenticationFilter**: 폼 기반 로그인 요청을 처리하여 사용자 인증을 수행
8. **DefaultLoginPageGeneratingFilter**: 기본 로그인 페이지를 생성
9. **DefaultLogoutPageGeneratingFilter**: 기본 로그아웃 페이지를 생성
10. **BasicAuthenticationFilter**: HTTP Basic 인증을 처리
11. **RequestCacheAwareFilter**: 요청 캐시를 처리하여 인증 후 원래 요청으로 리다이렉트할 수 있도록 처리
12. **SecurityContextHolderAwareRequestFilter**: 보안 컨텍스트와 요청을 통합하여 보안 관련 메서드를 사용할 수 있함
13. **AnonymousAuthenticationFilter**: 인증되지 않은 사용자를 익명 사용자로 처리
14. **ExceptionTranslationFilter**: 인증 및 권한 부여 과정에서 발생하는 예외를 처리
15. **AuthorizationFilter**: 최종적으로 URL 접근 제어를 수행하여 요청에 대한 권한을 확인

<br>

```
추가로 알면 좋은 인증 필터들
BearerTokenAuthenticationFilter : JWT 및 OAuth 2.0 Bearer 토큰 기반 인증을 처리하는 필터
OAuth2LoginAuthenticationFilter : OAuth 2.0 로그인 인증을 처리하는 필터
AnonymousAuthenticationFilter : 인증되지 않은 사용자에게 기본적으로 익명 인증 객체를 할당하는 필터
```

필터 체인은 추가하거나 비활성화할 수 있다.

`SecurityConfig` 에서 전체적인 보안 설정을 할 수 있다.

<br><br>

### SecurityConfig

SecurityConfig를 활성화하기 위해선 `@EnableWebSecurity`어노테이션을 붙여줘야한다.

`@EnableWebSecurity` 는보안 필터 체인을 활성화해 든 HTTP 요청이 보안 검사를 받으며, 요청이 필터 체인을 통해 처리된다.
`SecurityConfig` 를 작성하는데는 여러 방식이 있다. 

<br>

**`WebSecurityConfigurerAdapter`를 상속하는 방식**

```java
@Configuration 
@EnableWebSecurity 
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().authenticated()
                .and()
                .formLogin().permitAll();
        }
    
}
```
`configure(HttpSecurity http)` 메서드를 재정의해 원하는 보안 정책을 정의할 수 있다.

<br>

**`SecurityFilterChain` 빈 사용하는 방식**


```java
package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
```
Spring Security 5.7 이후부터는 `WebSecurityConfigurerAdapter` 대신 `SecurityFilterChain`을 사용하여 보안 설정을 구성하는 것이 권장한다.

<br><br>

두 방식 모두 `HttpSecurity` 객체 를 통해 보안 정책을 설정한다.

- `authorizeRequests()`: 요청에 대한 접근 권한을 설정한다. 예를 들어, 특정 URL 패턴에 대한 접근 권한을 정의할 수 있다.
    - `.antMatchers("/public/**").permitAll()`: `/public/**` 경로는 모든 사용자에게 허용
    - `.anyRequest().authenticated()`: 나머지 모든 요청은 인증된 사용자만 접근할 수 있다.
- `formLogin()`: 폼 기반 로그인을 설정
    - `.loginPage("/login")`: 커스텀 로그인 페이지를 설정
    - `.permitAll()`: 로그인 페이지에 누구나 접근할 수 있도록 허용
- `httpBasic()`: HTTP Basic 인증을 활성화
- `logout()`: 로그아웃 기능을 설정
    - `.logoutUrl("/logout")`: 커스텀 로그아웃 URL을 지정
- `csrf()`: CSRF(Cross-Site Request Forgery) 보호를 설정하거나 비활성화
- `sessionManagement()`: 세션 관리 정책을 설정
    - **`.**sessionCreationPolicy(SessionCreationPolicy.STATELESS)`: 세션을 사용하지 않고, 각 요청을 독립적으로 처리하도록 설정. 주로 JWT와 같은 토큰 기반 인증에서 사용
- `rememberMe()` : "Remember Me" 기능을 설정하여, 사용자가 애플리케이션에 다시 방문할 때 자동으로 로그인되도록한다.
- `exceptionHandling()`: 예외 처리 전략을 설정
    - `.accessDeniedPage("/accessDenied")`: 접근 권한이 없을 때 사용자에게 보여줄 페이지를 설정할 수 있다.


<br>
사용 예시

**기본 폼 로그인 설정**:

```java
http
    .authorizeRequests()
        .anyRequest().authenticated() // 모든 요청은 인증 필요
    .and()
    .formLogin().permitAll(); // 기본 로그인 폼 사용
```

<br>

**특정 경로에 대해 접근 제어 설정**:

```java
http
    .authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN") // /admin/** 경로는 ADMIN 권한 필요
        .antMatchers("/public/**").permitAll() // /public/** 경로는 누구나 접근 가능
        .anyRequest().authenticated() // 나머지는 인증 필요
    .and()
    .formLogin().permitAll(); // 기본 로그인 폼 사용

```

<br>

**HTTP Basic 인증 활성화**

```java
http
    .authorizeRequests()
        .anyRequest().authenticated()
    .and()
    .httpBasic(); // HTTP Basic 인증 사용

```

<br>

> **💡HTTP Basic ?**
HTTP Basic 인증은 클라이언트가 요청을 보낼 때 사용자 이름과 비밀번호를 `Authorization` 헤더에 인코딩하여 서버로 전송하는 간단한 인증 메커니즘이다. 하지만 암호화가 아닌 단순히 인코딩이기 때문에 HTTPS사용해야 한다. JWT, OAuth 2.0가 보다 보안에 좋다.
> 

<br><br>

### 커스텀 필터

커스텀 필터를 만드는 방법은  `Filter`를 구현해 `doFilter()`를 재정의하는 방식과 `OncePerRequestFilter`를 상속받아 `doFilterInternal()`를 재정의 하는 방법이 있다. 여기선 `Filter`를 구현해 `doFilter()`를 재정의 하고 필터체인에 추가해보겠다.

```java
public class CoustomFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String tokenId = request.getHeader("token"); 
        boolean hasAccess = isUserAllowed(tokenId); 
        if (hasAccess) {
            filterChain.doFilter(request, response); 
            return;
        }
        throw new AccessDeniedException("Access denied"); 
    }
    
    // 단순한 권한 검사 로직
    private boolean isUserAllowed(String tokenId) {
        return tokenId != null;
    }

}
```

요청 header에서 `tokenId`를 가져와 `null`인지 체크하는 필터이다.

`CoustomFilter` 가 호출되면  `doFilter()` 실행를 실행해 인증을 시작한다. 인증에 성공하면 `filterChain.doFilter(request, response)` 를 통해 **현재 필터에서 다음 필터로 요청과 응답을 전달**한고 실패하면 `AccessDeniedException` 을 발생한다.

이제 커스텀한 필터를 필터체인에 추가해보자.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomFilter customFilter;

    public SecurityConfig(CustomFilter customFilter) {
        this.customFilter = customFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            // 특정 필터 앞에 커스텀 필터 추가
            .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

내 CoustomFilter가 form기반 userId와 password를 인증하기 전에 실행하고 싶다면 `.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)` 이렇게 하면 실행 순서를 정할 수 있다.

- **`addFilterBefore()`**: 지정된 필터 전에 커스텀 필터를 실행
- **`addFilterAfter()`**: 지정된 필터 후에 커스텀 필터를 실행
- **`addFilterAt()`**: 지정된 필터와 정확히 같은 위치에 커스텀 필터를 배치

<br><br>

## 인증

### SecurityContextHolder, SecurityContext, Authentication

![image.png](/Spring/img/springSecurity(5).png)

<br>

`SecurityContextHolder`는 Spring Security에서 인증 정보를 전역적으로 유지하기 위한 객체이다.
이 객체는 `SecurityContext`를 포함하고 있으며, `SecurityContext` 안에는 `Authentication` 객체가 포함되어 있다.

`Authentication` 객체는 사용자 인증과 관련된 핵심 정보를 담고 있다.

1. **Principal**: 인증된 사용자 또는 시스템을 나타내는 주체로, 일반적으로 사용자 이름이나 사용자 객체
2. **Credentials**: 사용자의 인증을 위한 자격 증명으로, 보통 비밀번호와 같은 정보
3. **Authorities**: 사용자가 가진 권한이나 역할


<br>

Spring Security 인증의 핵심은 `SecurityContextHolder`이다.

`SecurityContextHolder`는 어플리케이션 어디서나 접근 가능한 글로벌 객체이다. 이 객체는 모든 인증된 사용자 정보를 포함하고 있어 어플리케이션 전반에서 인증 정보를 활용할 수 있도록 한다.

하지만, 모든 스레드가 하나의 `SecurityContext`를 공유하게 되면 **동시성 문제**와 **보안 문제**가 발생할 수 있다. 예를 들어, 하나의 스레드에서 인증 정보를 수정하거나 접근할 경우, 다른 스레드의 인증 상태도 영향을 받을 수 있다. 이러한 문제를 방지하기 위해 Spring Security는 `ThreadLocal`을 사용하여 각 스레드마다 고유한 인증 정보를 유지한다

`ThreadLocal`을 사용함으로써 각 스레드는 `SecurityContextHolder`를 통해 자신만의 `SecurityContext`를 가지며, 다른 스레드의 `SecurityContext`에 접근하거나 영향을 주지 않는다.

<br><br><br><br>

## 흐름 정리
![image.png](/Spring/img/SecurityFlow.png)

    1️⃣ 사용자가 클라이언트에서 로그인 폼에 아디 비번을 써서 로그인 버튼을 누름(보통 post/login 의 엔드포인트로 요청이 감. 

    (이 엔드포인트는 스프링 시큐리티에서 기본으로 제공하는 엔드포인트로 UsernamePasswordAuthenticationFilter에서 처리가 되기 때문에 컨트롤러에서 직접 처리되는 것이 아닌 스프링 시큐리티 필터체인에서 처리됨. )

    2️⃣ 이 요청을 서블릿 컨테이너의 필터체인에서 스프링 시큐리티의 필터 체인으로 전달함. 

    ⇒ 이 때 UsernamePasswordAuthenticationFilter(`AuthenticationFilter`) 가 이 요청을 가로채고 사용자가 제출한 아이디와 비번을 추출함. 

    ⇒ UsernamePasswordAuthenticationFilter은 이 정보를 이용해서 `UsernamePasswordAuthenticationToken`이라는 객체를 생성함. 

    ⇒ 이 객체는 사용자가 입력한 인증 정보를 담고 있음. (아이디, 비번)

    3️⃣이 토큰을 `AuthenticationManager`로 전달해서 인증을 시도함. 

    4️⃣ AuthenticationManager은 `AuthenticationProvider`를 통해 사용자 인증정보를 가져올 

    5️⃣UserDetailsService 객체에게 사용자 아이디를 넘겨주고 DB에서 인증에 사용할 사용자 정보 
    (사용자 아이디, 암호화된 패스워드 등) 을 

    6️⃣ UserDetails(인증용 객체와 도메인 객체를 분리하지 앟기 위해서 실제 사용되는 도메인 객체에 UserDetails를 상속하기도 한다.) 라는 객체로 전달 받는다. 

    7️⃣ 8️⃣ 9️⃣인증이 성공하면 AuthenticationProvider는 인증된 사용자의 정보를 포함한 Authentication 객체를 반환함. 

    🔟 Authentication 객체는 SecurityContext에 저장되고 이는 SecurityContextHolder에 의해 관리되며 현재 스레드에서 전역적 접근이 가능함. 

    이후…

    - `SecurityContext`는 현재 사용자의 인증 정보를 담고, 이후 요청에서 이 정보를 사용하여 사용자의 인가를 처리함.
    - 인증이 완료된 현시점 스프링 시큐리티는 기본적으로 사용자의 Authentication 객체를 세션에 저장해서 이후의 요청에서도 사용자가 인증된 상태임을 유지함. ⇒ 보안 설정에 따라 새로운 세션 생성이 될 수도 있고, 이는 세션 고정 공격을 방지하기 위한 조치임.
    - 이후 사용자가 서버에 다른 요청을 보내면 스프링 시큐리티는 요청을 다시 필터체인으로 보냄.
    - 이 때 SecurityContext에 저장된 Authentication 객체를 기반으로 FilterSecurityInterceptor가 사용자가 요청한 리소스에 접근할 권한이 있나 확인함. 권한이 있으면 요청이 정상 처리되고 그렇지 않으면 접근 거부 exception 방생.
    - 인증과 인가 처리가 완료되면 요청은 컨트롤러로 전달되어 실제 비즈니스 로직이 처리됨.
    - 컨트롤러는 처리된 결과를 응답으로 반환하며, 이 때 사용자의 인증 상태에 다라 개인화된 정보를 제공가능.
    - 사용자가 로그아웃 하려하면 LogoutFilter가 이 요청을 가로채고
    - SecurityContext에서 Authentication 객체를 제거함.
    - 또, 세션을 무효화하여 사용자의 인증 정보를 서버에서 삭제함.



<br><br><br><br>

## 총 정리

<br>
# 1. Spring Security filter chain이란

스프링 시큐리티는 여러 개의 필터로 구성된 필터체인을 사용하여 보안 기능을 처리합니당. 
이 필터들은 특정 순서에 따라 실행되며, 인증, 인가, CSRF 보호 등의 다양한 보안 기능을 수행합니당. 

- **SecurityContextPersistenceFilter**: 요청의 SecurityContext를 로드하거나 저장하는 역할을 합니다. 인증 정보를 유지하기 위해 사용됩니다.
- **UsernamePasswordAuthenticationFilter**: 사용자 이름과 비밀번호로 인증을 시도하는 필터입니다. 기본적인 폼 기반 로그인 요청을 처리합니다.
- **ExceptionTranslationFilter**: 인증이나 인가 과정에서 발생한 예외를 처리합니다.
- **FilterSecurityInterceptor**: 인가(Authorization) 과정을 처리하며, 요청에 대한 접근 권한을 결정합니다.
⇒ 필터 체인의 마지막에 있어서 인가를처리함. 
요청된 URL이나 메소드에 접근 권한이 있는지를 확인하여, 접근이 허용되면 요청을 계속 진행하고, 그렇지 않으면 접근 거부를 발생시킴.

# 2. Authentication과 Authorization ?

스프링 시큐리티는 AuthenticationManager를 통해 사용자의 인증을 처리합니다. AuthenticationProvider가 실제 인증 작업을 수행하며, 여러 AuthenticationProvider를 설정할 수 있습니다. 인증이 성공하면 Authentication 객체가 SecurityContext에 저장됩니다. 이후 Authorization은 FilterSecurityInterceptor에 의해 처리되며, 사용자가 요청한 리소스에 접근할 수 있는지 결정합니다.

- **AuthenticationManager**: 인증 요청을 처리하는 인터페이스입니다.
- **AuthenticationProvider**: 실제 인증 작업을 담당하며, 여러 개의 Provider를 설정할 수 있습니다.
- **SecurityContext**: 현재 사용자의 인증 정보를 저장하는 컨텍스트입니다.

# **3. SecurityContext를 통해 어떤 정보를 관리하나요?**

`SecurityContext`는 현재 인증된 사용자의 인증 정보를 관리하는 객체입니다. 
이 객체는 주로 `Authentication` 객체를 포함하며, `Authentication` 객체에는 사용자의 인증된 상태와 권한(Role) 정보가 들어 있습니다. 
`SecurityContext`는 요청마다 유지되며, 기본적으로 `SecurityContextHolder`를 통해 전역적으로 접근할 수 있습니다.

# 4. **Authentication 객체가 생성된 이후에는 어떻게 동작이 진행되나요?**

인증이 성공하여 `Authentication` 객체가 생성되면, 이 객체는 `SecurityContext`에 저장됩니다. 이후 요청에서 스프링 시큐리티는 `SecurityContext`를 참조하여 사용자가 인증된 상태인지 확인합니다. 또한, `Authentication` 객체에 포함된 권한 정보를 기반으로 인가 절차를 진행하며, 사용자가 요청한 리소스에 접근할 수 있는지를 결정합니다.

<br><br>
<hr>
[https://velog.io/@soyeon207/SpringBoot-스프링-시큐리티란](https://velog.io/@soyeon207/SpringBoot-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0%EB%9E%80)

[https://www.youtube.com/results?search_query=개발자+유미+시큐리티](https://www.youtube.com/results?search_query=%EA%B0%9C%EB%B0%9C%EC%9E%90+%EC%9C%A0%EB%AF%B8+%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0)
https://github.com/Afdddd/TIL/blob/main/Spring/SpringSecurity.md