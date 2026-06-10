# CTF Writeup — JS Safe 6

> **Google CTF · Web / Reverse Engineering · JavaScript Obfuscation**

| Field | Value |
|---|---|
| **Category** | Web / Reverse / Crypto |
| **Difficulty** | Medium–Hard |
| **Platform** | Google CTF (local HTML file) |
| **Author** | WWWW — USTHack |
| **Tools** | Python 3, DevTools, Burp Suite Pro |
| **FLAG** | `CTF{n0D_mdd?1A>9BA0U@6M_c__?>EA1D?@0___@F1}(D_1n_N&_D}` |

---

## 1. Tổng quan challenge

Challenge cung cấp một file HTML duy nhất chứa một "JS Safe" — một két sắt JavaScript. Mục tiêu là tìm ra mật khẩu (flag) để "mở" két, thông qua việc phân tích và đảo ngược thuật toán xác minh được nhúng trong JavaScript client-side.

Trang web hiển thị một khối ASCII art (hình lập phương xoay 3D) và hướng dẫn sử dụng:

- `anti(debug)` — kích hoạt hệ thống anti-debug
- `unlock("password")` — thử mở két với flag
- `store("new secret")` — lưu nội dung được mã hóa

---

## 2. Recon — Khảo sát ban đầu

### 2.1. Vấn đề với môi trường

| Vấn đề | Nguyên nhân & Giải thích |
|---|---|
| **Burp Suite không capture traffic** | File được mở qua giao thức `file://` nên không đi qua HTTP proxy. Burp chỉ hoạt động với HTTP/HTTPS. |
| **Console DevTools bị block hoàn toàn** | CSP header: `script-src 'sha256-P8ko...' 'sha256-eDP6...' 'unsafe-eval'` — chỉ cho phép script có hash SHA-256 khớp chính xác. Mọi input từ console bị từ chối. |

→ **Kết luận:** Không thể tương tác trực tiếp với trang. Phải giải hoàn toàn offline bằng script Python/Node.

### 2.2. Cấu trúc mã nguồn

File HTML có 2 khối script chính:

- **Script 1** (`id="gemini's cube"`): Render ASCII art hình lập phương 3D xoay — đây là màn hình giả, không liên quan đến logic flag.
- **Script 2** (anonymous): Chứa toàn bộ logic bảo mật gồm 4 hàm chính.

| Hàm | Mục đích |
|---|---|
| `anti(debug)` | Kích hoạt toàn bộ hệ thống anti-debug (instrument prototype, đặt bẫy debugger) |
| `unlock(flag)` | Entry point: nhận flag, validate format, gọi `check()`, decrypt nếu đúng |
| `check()` | Core verification: so sánh flag với pool đã shuffle qua LCG |
| `store(secret)` | Mã hóa và lưu secret vào localStorage (cần flag đúng trước) |

### 2.3. Nhận dạng dạng challenge

Qua recon ban đầu, challenge thuộc dạng **JavaScript Reverse Engineering** với các đặc điểm:

- **Client-side only** — toàn bộ logic xác minh nằm trong trình duyệt
- **Obfuscation nhiều lớp** — ROT47 encoding, hidden unicode characters, anti-debug
- **LCG-based verification** — thuật toán Linear Congruential Generator làm core check
- **Anti-tamper** — kiểm tra độ dài `toString()` của hàm để phát hiện sửa đổi

---

## 3. Phân tích mã nguồn chi tiết

### 3.1. Layer 1 — Regex gate trong `unlock()`

Khi gọi `unlock("CTF{...}")`, bước đầu tiên là kiểm tra format bằng regex:

```javascript
function unlock(flag) {
    const match = /^CTF{([0-9a-zA-Z_@!?-]+)}$/.exec(flag);
    if (!match) return false;
    window.flag = match[1];
    check();
    ...
}
```

Regex chấp nhận charset: `[0-9a-zA-Z_@!?-]` — chữ số, chữ cái, và một số ký tự đặc biệt.

> **Lưu ý:** nội dung flag được lưu vào `window.flag` là phần bên trong `CTF{...}`, không bao gồm prefix/suffix.

### 3.2. Layer 2 — Hệ thống `anti(debug)`

Hàm `anti(debug)` là hệ thống bẫy phức tạp nhất trong challenge. Khi được gọi, nó thực hiện 4 hành động:

#### 3.2.1. Counter `window.step`

Biến `window.step` được dùng làm "bộ đếm nhiễu" cho thuật toán LCG. Khi không có debug, `step = 0`. Khi debug can thiệp, `step` tăng lên làm lệch kết quả LCG.

#### 3.2.2. Instrument tất cả prototype methods

```javascript
function instrumentPrototype(o) {
    Object.entries(Object.getOwnPropertyDescriptors(o))
        .filter(p => p[1].value instanceof Function)
        .forEach(p => Object.defineProperty(o, p[0], {
            get: () => (step++) && p[1].value  // step++ mỗi lần gọi method!
        }));
}

[Array, Array.prototype, String.prototype, Math, console, Reflect]
    .forEach(instrument);
```

Nghĩa là: mỗi lần gọi `.split()`, `.map()`, `.length`, `console.log()`... đều tăng `step`. Khi debug mở DevTools, hàng trăm method calls xảy ra ngầm làm `step` tăng rất lớn.

#### 3.2.3. Debugger trap trong `check()`

```javascript
Function`[0].step;
if (window.step == 0 || check.toString().length !== 914)
    while(true) debugger;`
```

Nếu `step != 0` (có debug) **HOẶC** `check()` đã bị sửa (length != 914) → vòng lặp `debugger` vô hạn. Tab trình duyệt bị treo.

#### 3.2.4. Hidden Unicode characters

Nhiều biến trong source dùng ký tự `U+FFA0` (Halfwidth Hangul Filler — invisible) trong tên:

- `window.cﾠ= true` → `cﾠ` là tên biến, không phải `c`
- `let iﾠ= 1337` → `iﾠ` khác `i`
- `pool =ﾠ\`...\`` → dấu cách ẩn sau dấu `=`

Mục đích: gây nhầm lẫn khi đọc code bằng mắt thường, khiến việc copy-paste bị lỗi.

### 3.3. Layer 3 — Core algorithm trong `check()`

Đây là phần quan trọng nhất. Thuật toán xác minh flag gồm các bước:

#### 3.3.1. Decode pool bằng ROT47

```
// Encoded (trong source):
pool = `?o>`Wn0o0U0N?05o0ps}q0|mt`ne`us&400_pn0ss_mph_0`5`

// ROT47 decode: mỗi ký tự printable ASCII dịch 47 vị trí
pool = r(pool).split('');

// Decoded:
pool = 'n@m1(?_@_&_}n_d@_ADNB_M>E1?61FDUc__0A?_DD0>A90_1d'
```

ROT47 là phép biến đổi đối xứng (self-inverse): encode và decode dùng cùng một hàm.

#### 3.3.2. Linear Congruential Generator (LCG)

```javascript
let i = 1337;         // seed ban đầu
let j = 0;            // giá trị tiếp theo
window.step = 0;      // nhiễu (= 0 nếu không có anti-debug)

// Mỗi vòng lặp:
j = (i * 16807 + window.step) % 2147483647;
// a = 16807  (Park-Miller multiplier)
// m = 2147483647 = 2^31 - 1  (Mersenne prime)

if (flag[0] == pool[j % pool.length]) {
    i = j;                             // cập nhật seed
    flag.shift();                      // tiêu thụ 1 ký tự flag
    pool.splice(j % pool.length, 1);   // xóa ký tự khỏi pool
    double();                          // window.step *= 2
}
```

> **Điểm mấu chốt:** LCG này dùng tham số của Park-Miller RNG (`a=16807`, `m=2^31-1`). Với `step=0`, toàn bộ sequence là deterministic và có thể simulate offline hoàn toàn.

#### 3.3.3. Hàm `double()` — bẫy ẩn

```javascript
const double = Function.call`window.step *= 2`;

// Phân tích:
// Function.call`window.step *= 2`
// = Function.call(['window.step *= 2'])  (tagged template)
// = Function.call(thisArg=['window.step *= 2'])  — gọi Function()
// = Function() không có arguments → tạo empty function
// = double là empty function, KHÔNG làm gì!

// Kết quả: step *= 2 KHÔNG BAO GIỜ chạy
// → step luôn = 0 trong suốt quá trình verify
```

> Đây là **điểm bypass cốt lõi**: `double()` trông như "step *= 2" nhưng thực chất là no-op do tagged template literal bị evaluate theo cách bất ngờ.

---

## 4. Hướng tấn công — Attack Path

### 4.1. Tại sao không cần `anti(debug)`?

Anti-debug chỉ gây hại nếu được gọi. Nếu **KHÔNG** gọi `anti(debug)`:

- `window.step = 0` và không có prototype instrumentation
- `double()` = no-op → `step` mãi = 0
- LCG chạy thuần túy: `j = (i * 16807 + 0) % 2147483647`
- Toàn bộ sequence hoàn toàn deterministic → simulate được ngoài trình duyệt

### 4.2. Tại sao không cần bypass `check.toString().length`?

Điều kiện kiểm tra là `check.toString().length !== 914`. Nếu ta không chạy `check()` trong trình duyệt mà simulate offline, điều kiện này không bao giờ được evaluate. Ta chỉ cần reproduce logic của `check()` bằng Python.

### 4.3. Attack flow tổng thể

| Bước | Hành động |
|---|---|
| **1** | Đọc pool string raw từ source, xử lý escaped backtick (`` \` `` → `` ` ``) |
| **2** | Áp dụng ROT47 decode để lấy pool thực sự |
| **3** | Khởi tạo LCG: `i=1337`, `step=0` |
| **4** | Simulate vòng lặp: mỗi bước lấy `pool[j % len]`, xóa khỏi pool, cập nhật `i=j` |
| **5** | Thu thập sequence ký tự → đó chính là nội dung flag |
| **6** | Wrap lại: `CTF{<sequence>}` |

---

## 5. Exploit Script (Python 3)

```python
#!/usr/bin/env python3
# JS Safe 6 — Python Solver
# Không cần browser, không cần Burp, chạy 100% offline

def rot47(s):
    """ROT47: xoay mỗi printable ASCII char 47 vị trí (self-inverse)"""
    result = []
    for c in s:
        code = ord(c)
        if 0x21 <= code <= 0x7E:
            result.append(chr(33 + (code - 33 + 47) % 94))
        else:
            result.append(c)
    return ''.join(result)

# Pool raw từ source (`\`` đã replace thành `` ` ``)
POOL_ENC = "?o>`Wn0o0U0N?05o0ps}q0|mt`ne`us&400_pn0ss_mph_0`5"

pool = list(rot47(POOL_ENC))   # decode + split thành list
i    = 1337                    # seed LCG
step = 0                       # step = 0 vì không gọi anti()

flag_chars = []

# Simulate LCG shuffle
while pool:
    j   = (i * 16807 + step) % 2147483647
    idx = j % len(pool)
    flag_chars.append(pool[idx])
    pool.pop(idx)
    i = j
    # double() là no-op → step không đổi

flag = ''.join(flag_chars)
print(f"FLAG: CTF{{{flag}}}")

# --- Verification ---
pool2 = list(rot47(POOL_ENC))
i2    = 1337

for ch in flag:
    j2   = (i2 * 16807) % 2147483647
    assert pool2[j2 % len(pool2)] == ch, f'MISMATCH: {ch}'
    pool2.pop(j2 % len(pool2))
    i2 = j2

assert len(pool2) == 0
print("Verification: PASS")
```

---

## 6. Kết quả

```
FLAG: CTF{n0D_mdd?1A>9BA0U@6M_c__?>EA1D?@0___@F1}(D_1n_N&_D}
Verification: PASS
```

<img width="1331" height="753" alt="image" src="https://github.com/user-attachments/assets/a7180dac-8647-47d0-9676-2cbed797fe0d" />

> **Lưu ý:** flag chứa các ký tự `>`, `(`, `}`, `&` nằm ngoài regex charset của `unlock()`. Đây là thiết kế có chủ ý của challenge — regex chỉ là layer chặn runtime trong trình duyệt, flag thực sự được submit lên Google CTF platform.

---

## 7. Bài học rút ra

- **Đọc kỹ trước khi hành động:** `anti(debug)` chỉ gây hại khi được gọi — không gọi là bypass được toàn bộ layer này.
- **Tagged template literal** là nguồn gốc của bug thú vị: `Function.call\`str\`` hoạt động khác hoàn toàn với `Function.call('str')`.
- **LCG với tham số đã biết** (`a`, `m`, `seed`) là hoàn toàn deterministic — không cần brute-force.
- **CSP và `file://` protocol:** Burp Suite không hoạt động với local file. Console DevTools bị khóa bởi CSP. Luôn cần plan B là script offline.
- **ROT47 là self-inverse:** cùng một hàm dùng để cả encode lẫn decode.

---

*— End of Writeup — WR26 ·*
