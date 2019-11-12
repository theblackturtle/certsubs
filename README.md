# certsubs
A simple tool to get subdomain from SSL Certificate
### Usage
```
Usage of ./certsubs:
  -p string
        Ports to connect, separate with comma. (default "443")
  -t int
        Threads to use. (default 5)
```
### Example
```
cat domains.txt | ./certsubs -p 8080,443,8888 -t 10
```