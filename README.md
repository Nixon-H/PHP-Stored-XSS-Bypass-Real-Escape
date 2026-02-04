## Executive Summary

A comprehensive security assessment was performed on the local instance of the E-commerce application. The assessment identified **four Critical and High-severity vulnerabilities** stemming from systemic flaws in input validation, session management, and access control implementation. Thois is mere one from others.

**Disclosure Timeline Update:**

* **December 16, 2025:** Initial contact attempted via email and this GitHub issue.
* **December 23, 2025:** Disclosure deadline passed. No response received from the maintainer.
* **December 26, 2025:** Proceeding with full disclosure in accordance with standard responsible disclosure guidelines to warn the community.


### **Disclosure Reference**

The issues detailed in these repositories were reported to the project maintainers in accordance with responsible disclosure practices. Full technical details are being released following the expiration of the disclosure deadline without response.

**Official Bug Report:** [GitHub Issue #23: Multiple Critical Vulnerabilities](https://github.com/detronetdip/E-commerce/issues/23)

---

## Vulnerability: Stored Cross-Site Scripting (XSS)

**Severity:** **HIGH** (7.6)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`
**Bug Type:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### Description

The application contains a Stored Cross-Site Scripting (XSS) vulnerability due to insufficient input sanitization in the core utility functions. The function intended to clean inputs, `get_safe_value()`, only employs `mysqli_real_escape_string`. This function escapes characters for SQL queries (preventing SQL Injection) but does **not** encode HTML entities (such as `<` and `>`).

An attacker can use the previously identified IDOR vulnerability to inject malicious JavaScript payloads into product fields (such as `product_name` or `description`). This payload is stored in the database. When an administrator views the product list or approves products in the backend dashboard, the malicious script executes within the administrator's browser session.

### Vulnerable Files

* **Root Cause:** `utility/function.php` (Insecure `get_safe_value` function)
* **Injection Point:** `seller/assets/backend/product/updateproduct.php`

### Vulnerable Code Analysis

**File:** `utility/function.php`

```php
function get_safe_value($con, $str)
{
    if ($str != '') {
        $str = trim($str);
        // FLAW: Only protects against SQL Injection.
        // Does NOT protect against XSS (e.g., does not use htmlspecialchars).
        return mysqli_real_escape_string($con, $str);
    }
}

```

### Exploit Proof of Concept (PoC)

**Exploit Command:**
The attacker injects a JavaScript payload designed to alert a message (or steal cookies) into the Product Name field.

```bash
curl -X POST \
  -H "Cookie: PHPSESSID=[Session_ID]" \
  -d "id=10" \
  -d "name=<script>alert('XSS_ADMIN_TAKEOVER')</script>" \
  -d "price=1000" \
  -d "sellprice=1" \
  -d "quantity=10" \
  "http://localhost:3000/seller/assets/backend/product/updateproduct.php"

```

**Execution Scenario:**

1. Attacker executes the curl command.
2. Database stores `Product Name` as `<script>alert('XSS_ADMIN_TAKEOVER')</script>`.
3. Administrator logs in and visits the "Product Approval" page.
4. The browser renders the product list, encounters the `<script>` tag, and executes the alert.

### Impact

* **Session Hijacking:** Attackers can inject scripts to steal the Administrator's `PHPSESSID` cookies (`document.cookie`), allowing full account takeover.
* **Persistent Malware:** The script executes every time the affected page is loaded, potentially re-infecting the admin or other users repeatedly.
* **Phishing/Defacement:** Attackers can rewrite the page content (DOM) to display fake login forms or misleading information.


## Remediation Recommendations

### Implement Output Encoding (XSS Fix)

To mitigate XSS, data must be sanitized before being output to the browser.

* **Update `get_safe_value`:** While this function handles SQL injection, a separate step is needed for output.
* **Output Encoding:** When displaying data in HTML (e.g., in the Admin dashboard), always wrap variables in `htmlspecialchars()`.
* *Vulnerable:* `echo $row['product_name'];`
* *Secure:* `echo htmlspecialchars($row['product_name'], ENT_QUOTES, 'UTF-8');`
