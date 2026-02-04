# PHP-Stored-XSS-Bypass-Real-Escape
A High-severity (7.6) Stored XSS vulnerability. The system uses mysqli_real_escape_string for sanitization, which fails to stop HTML injection. Attackers can inject malicious scripts into product fields to steal administrator session cookies and perform account takeovers.
