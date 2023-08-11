
# Generate the Private Key and Certificate Signing Request (CSR)
openssl req -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr -subj "/CN=localhost"

# Generate the Self-Signed Certificate
openssl x509 -req -sha256 -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
