# 🔐 Microservices Security – EazyBank 

This section is an **advancement of the Observability & Monitoring module**, where we introduce **security into EazyBank microservices** using **OAuth 2.0, OpenID Connect, Spring Security, and Keycloak**.

The goal is to ensure:
- Secure API access
- Token-based authentication
- Centralized identity management
- Role-based authorization at API Gateway level

---

## 🚧 Challenges Solved Using Microservices Security

By implementing **Spring Security + OAuth2 + OpenID Connect + Keycloak**, we solve:

- ❌ Unauthorized access to APIs  
- ❌ No centralized authentication system  
- ❌ Credential sharing between services  
- ❌ Lack of token-based security  
- ❌ No role-based access control  
- ❌ Difficult identity & access management  
- ❌ No standard security protocol  
- ❌ Poor scalability of custom auth logic  
- ❌ Security gaps at API Gateway  

---

## 🔑 What Is OAuth 2.0?

### 📘 Definition
**OAuth 2.0 (Open Authorization 2.0)** is an **industry-standard authorization framework** that allows a client application to access protected resources on behalf of a user or another service **without exposing credentials** such as usernames and passwords.

OAuth 2.0 focuses strictly on **authorization**, not authentication.

In a microservices and cloud-native architecture, OAuth 2.0 enables **secure, delegated access** by issuing **access tokens** that represent permissions granted by a resource owner.

It focuses on:
- *Who* can access
- *What* can be accessed
- *For how long*

---

## 🧠 OAuth 2.0 Terminology

### 1️⃣ Resource Owner  
The entity that owns the protected resource (user or service).

### 2️⃣ Client  
The application requesting access (e.g., API client).

### 3️⃣ Authorization Server  
Issues access tokens after authentication (**Keycloak**).

### 4️⃣ Resource Server  
Hosts protected APIs and validates tokens (**API Gateway**).

### 5️⃣ Scopes  
Permissions granted to the access token (e.g., `openid`, `profile`, `email`).

---

## 🆔 What Is OpenID Connect (OIDC)?


**OpenID Connect (OIDC)** is an **identity layer built on top of OAuth 2.0** that adds **authentication** capabilities.

While OAuth 2.0 answers:
> ❓ *What is this client allowed to access?*

OpenID Connect answers:
> ❓ *Who is the user?*

---

### 🧠 Why OpenID Connect Is Needed

OAuth 2.0 alone:
- Does NOT define user identity
- Only issues access tokens
- Cannot reliably authenticate users

OIDC extends OAuth 2.0 by:
- Introducing **ID Tokens**
- Standardizing user identity claims
- Enabling **Single Sign-On (SSO)**

---

### 🎯 What OpenID Connect Does

OpenID Connect:
- Authenticates users
- Provides verified user identity
- Issues **ID Tokens (JWTs)**
- Enables login, logout, and SSO
- Standardizes identity across systems


---

## 🔄 OAuth 2.0 + OpenID Connect Workflow

1. Client sends authentication request  
2. Authorization Server authenticates client  
3. Access Token (JWT) is issued  
4. Client sends request with Bearer token  
5. Resource Server validates token  
6. Access granted based on roles & scopes  

---

## 🛡️ What Is Keycloak?

**Keycloak** is an **open-source Identity and Access Management (IAM)** solution providing:

- OAuth 2.0 & OpenID Connect
- Authentication & Authorization
- JWT token management
- Role & client management

---

## ❓ Problems Solved by Keycloak

- Centralized authentication
- Token issuance & validation
- Role-based access control
- No custom security code
- Enterprise-grade IAM

---

## 🔐 Client Credentials Grant


**Client Credentials Grant** is an OAuth 2.0 authorization grant type used for **machine-to-machine (service-to-service) authentication**, where **no end user is involved**.

In this flow, a **client application authenticates itself** directly with the **Authorization Server** using its own credentials (**Client ID and Client Secret**) and receives an **access token**. This token is then used to securely access protected APIs.

This grant type is specifically designed for **backend systems, internal microservices, and trusted applications**.

---

## 🧠 Why Client Credentials Grant Is Needed

In microservices architecture:
- Services need to call **other services**
- There is **no user context**
- Credentials should **never be shared**
- Security must be **centralized**

Client Credentials Grant solves this by:
- Eliminating the need for user login
- Allowing secure service authentication
- Issuing short-lived access tokens
- Enforcing scope-based access

---

## 🎯 When to Use Client Credentials Grant

Use this grant type when:
- One backend service calls another backend service
- Scheduled jobs or batch processes access APIs
- API Gateways authenticate to downstream services
- Internal systems communicate securely

❌ **Do NOT use when a user is involved**

---

## 🔑 Key Characteristics

- No user interaction
- Token represents **the client**, not a user
- Highly secure for trusted systems
- Ideal for automation and internal APIs
- Uses OAuth 2.0 standard

---

## 🚀 Keycloak Setup (Auth Service)

### 🐳 Start Keycloak Using Docker

```bash
docker run -p 127.0.0.1:7080:8080 \
-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
quay.io/keycloak/keycloak:26.4.7 start-dev
```

- URL: http://localhost:7080  
- Username: `admin`  
- Password: `admin`  

---

## 🧩 Client Configuration in Keycloak

- **Client ID:** `eazybank-callcenter-cc`
- **Name:** Eazybank Callcenter App
- **Description:** Eazybank Callcenter App

### Settings:
- Enable **Client Authentication**
- Disable all flows
- Enable **Service Account Roles**
- Save client

### Credentials:
- Copy **Client Secret**

---

## 🔑 Generate Access Token (Client Credentials Flow)

- Copy `token_endpoint` from **OpenID Endpoint Configuration**

### Postman Request:
```text
POST {token_endpoint}

grant_type=client_credentials
client_id=eazybank_callcenter_cc
client_secret=xxxxxxxx
scope=openid email profile
```

✔️ Response contains Access Token (JWT)

---

## 🌐 Securing API Gateway (Resource Server)

### 📦 Dependencies

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
```

---

## 🔑 JWT Validation Configuration

```yaml
security:
  oauth2:
    resourceserver:
      jwt:
        jwk-set-uri: "http://localhost:7080/realms/master/protocol/openid-connect/certs"
```

---

## 🔒 Gateway Security Configuration

```java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {

        serverHttpSecurity.authorizeExchange(exchanges -> exchanges
                .pathMatchers(HttpMethod.GET).permitAll()
                .pathMatchers("/eazybank/accounts/**").hasRole("ACCOUNTS")
                .pathMatchers("/eazybank/cards/**").hasRole("CARDS")
                .pathMatchers("/eazybank/loans/**").hasRole("LOANS"))
            .oauth2ResourceServer(oAuth2 -> oAuth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor())));

        serverHttpSecurity.csrf(csrf -> csrf.disable());
        return serverHttpSecurity.build();
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}
```

---

