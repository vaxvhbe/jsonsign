build:
	go build -o bin/sign cmd/sign/main.go
	go build -o bin/validate cmd/validate/main.go

keys:
	openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in private.key -out public.key
