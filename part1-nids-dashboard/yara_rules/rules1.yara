/*
 * NIDS YARA Rules
 * Add custom YARA rules here for malware detection
 */

rule suspicious_powershell {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "NIDS Dashboard"
        severity = "high"
    
    strings:
        $s1 = "powershell.exe -enc" nocase
        $s2 = "powershell.exe -encodedcommand" nocase
        $s3 = "bypass -nop -c" nocase
    
    condition:
        any of them
}

rule suspicious_base64 {
    meta:
        description = "Detects long base64 strings (potential payload)"
        author = "NIDS Dashboard"
        severity = "medium"
    
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    
    condition:
        $b64
}

rule http_sensitive_data {
    meta:
        description = "Detects sensitive data in HTTP"
        author = "NIDS Dashboard"
        severity = "medium"
    
    strings:
        $password = "password" nocase
        $token = "authorization" nocase
        $api_key = "api_key" nocase
        $secret = "secret" nocase
    
    condition:
        any of them
}

rule sql_injection_pattern {
    meta:
        description = "Detects potential SQL injection patterns"
        author = "NIDS Dashboard"
        severity = "high"
    
    strings:
        $sqli1 = "' OR '1'='1" nocase
        $sqli2 = "UNION SELECT" nocase
        $sqli3 = "--" nocase
        $sqli4 = "DROP TABLE" nocase
        $sqli5 = "xp_cmdshell" nocase
    
    condition:
        any of them
}

rule web_shell_pattern {
    meta:
        description = "Detects web shell patterns"
        author = "NIDS Dashboard"
        severity = "critical"
    
    strings:
        $shell1 = "eval($_POST" nocase
        $shell2 = "system($_POST" nocase
        $shell3 = "exec($_FILES" nocase
        $shell4 = "base64_decode" nocase
    
    condition:
        any of them
}

rule reverse_shell_pattern {
    meta:
        description = "Detects reverse shell patterns"
        author = "NIDS Dashboard"
        severity = "critical"
    
    strings:
        $rev1 = "/bin/bash -i" nocase
        $rev2 = "nc -e /bin/bash" nocase
        $rev3 = "nc.exe -e cmd.exe" nocase
        $rev4 = "bash -i >& /dev/tcp" nocase
    
    condition:
        any of them
}

rule malware_indicator {
    meta:
        description = "Detects known malware indicators"
        author = "NIDS Dashboard"
        severity = "critical"
    
    strings:
        $m1 = "WannaCry" nocase
        $m2 = "Petya" nocase
        $m3 = "CryptoLocker" nocase
        $m4 = "Mirai" nocase
    
    condition:
        any of them
}

