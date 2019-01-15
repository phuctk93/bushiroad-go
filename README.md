# bushiroad-go
Bushiroad-go is backend of bushiroad game writen in golang
# How to run
## Config
Open [config.json](./config.json) with any text editor. Edit like you want:
- admin: add your admin account here
- hosts: add your hosts to CORS
- database: add posgresql config
- example: add fake data
- tls: enable https for back-end
- cert and key: required for tls to serve with https.
## Run
- Open terminal at current folder for linux server like Debian/ Ubuntu/ Fedora/ CentOS and type:
```
./bushiroad-go
```
New server will serve at localhost:5000
# How to build
## Required
- [Go](https://golang.org/dl/)
- [PosgresSQL](https://www.postgresql.org/download/)
- PosgresSQL driver for Golang
```
go get github.com/go-pg/pg
```
- Gin frame-work and some libraries of gin
```
go get github.com/gin-gonic/gin
go get github.com/gin-contrib/cors
```
- Go JWT:
```
go get github.com/dgrijalva/jwt-go
```
- Go shortid:
```
go get github.com/teris-io/shortid
```
## Build to run
- Open terminal at current folder with any OS and type:
```
go build && ./bushiroad-go
```
