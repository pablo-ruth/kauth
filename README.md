# Kauth

Create CA
```
mkdir -p certs
openssl genrsa -out certs/ca.key 2048
openssl req -new -key certs/ca.key -x509 -days 365 -out certs/ca.crt
```

Generate user cert
```
go run main.go -user foo -group teamA
```