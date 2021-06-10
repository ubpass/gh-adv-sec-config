# Unsafe deserialisation using jackson-databind polymorphic types
Jackson-databind supports deserialisation of polymorphic types. Certain configurations of this feature can expose applications to the deserialization of attacker controlled java objects. By using instances of classes that are known to perform unsafe object initialisation, the so called "gadgets", an attacker can cause malicious code to be executed by the application


## Recommendation
TODO: A few conditions must be met for this vulnerability to be exploited...


## Example
TODO: Some example HERE


## References
* [Overview of the vulnerability and recommendations](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062).
* [Vulnerability bulletim](https://www.cvedetails.com/cve/CVE-2017-7525/)
