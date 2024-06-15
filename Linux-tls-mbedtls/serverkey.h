/*
 * Title:  socks5 server key header (Linux)
 * Author: Shuichiro Endo
 */

/*
https://mbed-tls.readthedocs.io/en/latest/kb/how-to/generate-a-self-signed-certificate/

git clone --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls/programs
make

cd ../../
# rsa
mbedtls/programs/pkey/gen_key type=rsa rsa_keysize=4096 format=pem filename=server-private.pem
# ec
mbedtls/programs/pkey/gen_key type=ec ec_curve=secp256r1 format=pem filename=server-private.pem

mbedtls/programs/x509/cert_write selfsign=1 issuer_key=server-private.pem issuer_name=CN=socks5 not_before=20240101000000 not_after=21231231235959 is_ca=1 max_pathlen=0 format=pem output_file=server.crt

# rsa
cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END RSA PRIVATE KEY-----\\n"\\/"-----END RSA PRIVATE KEY-----\\n";/g'
# ec
cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'

cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
*/


char serverPrivateKey[] = "-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEIFY8dQBI0ANxrhcrNdkco60DKeL5Fp92fsnx2h+cjElxoAoGCCqGSM49\n"\
"AwEHoUQDQgAENM3ez4fy66/32rxwDzC4VQua26v39cN0+fYI31HJ1YDgMlvGAGbf\n"\
"VTWZ9tl/YIA1exfGMsgonGIVAGuY1hK8rQ==\n"\
"-----END EC PRIVATE KEY-----\n";

char serverCertificate[] = "-----BEGIN CERTIFICATE-----\n"\
"MIIBaTCCAQ+gAwIBAgIBATAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZzb2NrczUw\n"\
"IBcNMjQwMTAxMDAwMDAwWhgPMjEyMzEyMzEyMzU5NTlaMBExDzANBgNVBAMMBnNv\n"\
"Y2tzNTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDTN3s+H8uuv99q8cA8wuFUL\n"\
"mtur9/XDdPn2CN9RydWA4DJbxgBm31U1mfbZf2CANXsXxjLIKJxiFQBrmNYSvK2j\n"\
"VjBUMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPRIHhwlFBeGzArKxEiw\n"\
"/rd8tbjJMB8GA1UdIwQYMBaAFPRIHhwlFBeGzArKxEiw/rd8tbjJMAoGCCqGSM49\n"\
"BAMCA0gAMEUCIQDRtk+VhqPgOiCR/f+9uoTvDZ8DPxPOHPjgpGDQ//Ah+gIgaPAM\n"\
"RbKJncieOJskYWEUwTB3EkIeTQJg1PIoyFTOCpc=\n"\
"-----END CERTIFICATE-----\n";

