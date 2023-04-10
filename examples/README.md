# Simple server to generate signatures for testing
This server is leverage Postman ``Autonomy Postcard`` to generate signatures for testing.

## How to use
Run this simple server
```azure
go run main.go
```

Then, use Postman(Autonomy Postcard) to send a request to this server. The request should contain the following headers:
``X-Api-Timestamp``

