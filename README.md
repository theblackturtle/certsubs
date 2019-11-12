# certsubs
A simple tool to get subdomain from SSL Certificate
### Usage
```
Usage of ./certsubs:
  -d string
        Only get subdomains end with this domain.
  -p string
        Ports to connect, separate with comma. (default "443")
  -t int
        Threads to use. (default 5)
```
### Example
##### For single domain
```
./certsubs domain.com
```
##### For list domains
```
cat domains.txt | ./certsubs -p 8080,443,8888 -t 10 -d domain.com
```