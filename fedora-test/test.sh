#!/bin/bash
set -exo pipefail
dnf -y install /totpm.rpm swtpm

# Install should create user, data dir, config and SUID binary
[ -d "/var/lib/totpm" ]
[ -f "/etc/totpm.conf" ]
[ "$(ls -l /usr/bin/totpm | cut -d' ' -f1)" == "-rwsr-xr-x." ]
[ "$(ls -l /usr/bin/totpm | cut -d' ' -f3)" == "totpm" ]

sed -i 's/^tpm.*/tpm = "swtpm:host=127.0.0.1,port=12345"/' /etc/totpm.conf
sed -i 's/^pv_method.*/pv_method = "none"/' /etc/totpm.conf

mkdir /tmp/swtpm
swtpm socket \
    --tpmstate dir=/tmp/swtpm \
    --server type=tcp,port=12345 \
    --ctrl type=tcp,port=12346 \
    --tpm2 \
    --flags not-need-init &

useradd testuser
sudo -u testuser bash /user-test.sh

# Should have been created during user test, but not removed by local clear
[ "$(ls -l /var/lib/totpm/auth_value | cut -d' ' -f1)" == "-rw-------." ]
[ "$(ls -l /var/lib/totpm/auth_value | cut -d' ' -f3)" == "totpm" ]

# System clear should remove auth value
totpm clear --system --yes-i-know-what-i-am-doing
[ ! -e "/var/lib/totpm/auth_value" ]
