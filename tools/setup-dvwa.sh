#!/bin/sh
# Khoi tao / reset CSDL DVWA. Chay TRONG container 'attacker':
#   docker compose exec attacker sh -c "tr -d '\r' < /tools/setup-dvwa.sh | sh"
T=http://10.10.10.10
# Lay CSRF token tu trang setup (kem cookie)
token=$(curl -s -c /tmp/dvwa_c -b /tmp/dvwa_c "$T/setup.php" \
        | grep -o "user_token[^>]*value=.[0-9a-f]*" | grep -o "[0-9a-f]\{32\}")
# Bam nut "Create / Reset Database"
curl -s -c /tmp/dvwa_c -b /tmp/dvwa_c \
     --data "create_db=Create / Reset Database&user_token=$token" \
     "$T/setup.php" -o /dev/null -w "setup DVWA: HTTP %{http_code}\n"
