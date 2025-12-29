"""Test constants and HTML templates for web-vuln-scanner-mcp tests."""

# HTML response templates for testing
HTML_VULNERABLE_XSS = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Page</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: <script>alert('XSS')</script></p>
</body>
</html>
"""

HTML_SAFE = """
<!DOCTYPE html>
<html>
<head><title>Safe Page</title></head>
<body>
    <h1>Welcome</h1>
    <p>This is a safe page.</p>
</body>
</html>
"""

HTML_SQLI_ERROR_MYSQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>
</body>
</html>
"""

HTML_SQLI_ERROR_POSTGRESQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>PostgreSQL ERROR: syntax error at or near "'"</p>
</body>
</html>
"""

HTML_SQLI_ERROR_ORACLE = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Database Error</h1>
    <p>ORA-00933: SQL command not properly ended</p>
</body>
</html>
"""

HTML_SQLI_ERROR_MSSQL = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>Microsoft OLE DB Provider for ODBC Drivers error '80040e14' [Microsoft][ODBC SQL Server Driver]</p>
</body>
</html>
"""

HTML_SQLI_ERROR_SQLITE = """
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>SQLite3::Exception: near "'": syntax error</p>
</body>
</html>
"""

HTML_INFO_DISCLOSURE = """
<!DOCTYPE html>
<html>
<head><title>Debug Page</title></head>
<body>
    <h1>Debug Info</h1>
    <!-- TODO: Remove this before production -->
    <p>password = "admin123"</p>
    <p>api_key = "sk-12345abcde"</p>
    <p>AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"</p>
    <p>Internal Server: 192.168.1.100</p>
    <p>Path: /home/webuser/app/config.py</p>
    <pre>
    Stack trace at line 42:
    File "/home/webuser/app/main.py", line 42, in handle_request
        raise Exception("Debug error")
    </pre>
</body>
</html>
"""

HTML_PARTIAL_XSS = """
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    <input type="hidden" value="<script>al">
</body>
</html>
"""

SENSITIVE_GIT_CONFIG = """
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
[remote "origin"]
    url = git@github.com:user/secret-repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"""

SENSITIVE_ENV_FILE = """
DATABASE_URL=postgres://admin:secretpass@localhost:5432/mydb
SECRET_KEY=super-secret-key-12345
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
