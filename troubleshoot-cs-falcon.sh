#!/bin/bash
# We just need to compare the results, no need to compare the actual CID
# Prepare: echo $CID | sha256sum | cut -f1 -d\
FALCON_CID_HASH="<your-company's-cid>"

# Other things we may need to change at some point
FALCON_CLOUD_HOST="ts01-gyr-maverick.cloudsink.net"
FALCON_CLOUD_URL="https://${FALCON_CLOUD_HOST}"
FALCONCTL="/opt/CrowdStrike/falconctl"
CURL=$(which curl)

# Some fancy output coloring to make the output more obvious
if [ -t 1 ]; then # does stdout end up on a terminal?
    # Display fancy colors
    # ANSI colors
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    YELLOW=$(tput setaf 3)
    NC=$(tput sgr0) # No Color
else
    # Minimalist display
    # no colors
    GREEN=""
    YELLOW=""
    RED=""
    NC=""
fi

# Three classes of colored output
warning() {
    echo "${YELLOW}${1}${NC}"
}

alert() {
    echo "${RED}${1}${NC}"
}

ok() {
    echo "${GREEN}${1}${NC}"
}

# Prepare some workaround strings as a potential solutions for the teams
KERNEL_CHECK_INFO="[!] CS Falcon RFM state is set to false, so the kernel support info may be inaccurate"
read -r -d '' NETWORK_STATUS_WORKAROUND_INFO <<EOM
[!] Workaround suggestion

    It seems that CS sensor is not connected to the CS cloud for some reason,
    even though our other network checks seem to be ok.

    First option is to try restarting the sensor:

       $(ok "sudo systemctl restart falcon-sensor")

    If that doesn't help, you may want to try this:
      $(ok "
      sudo /opt/CrowdStrike/falconctl -s --backend=kernel
      sudo systemctl restart falcon-sensor
      sudo /opt/CrowdStrike/falconctl -d --backend")

    This may (or may not) help in your case.
EOM

is_ec2_instance() {
    # taken from: https://serverfault.com/questions/462903/how-to-know-if-a-machine-is-an-ec2-instance/700771#700771
    # This first, simple check will work for many older instance types.
    if [ -f /sys/hypervisor/uuid ]; then
        # File should be readable by non-root users.
        if [ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]; then
            echo yes
        else
            echo no
        fi

    # This check will work on newer m5/c5 instances, but only if you have root!
    elif [ -f /sys/devices/virtual/dmi/id/product_uuid ]; then
        # If the file exists AND is readable by us, we can rely on it.
        product_uuid=$(sudo head -c 3 /sys/devices/virtual/dmi/id/product_uuid)
        if [ "${product_uuid}" == "EC2" ] || [ "${product_uuid}" == "ec2" ]; then
            echo yes
        else
            echo no
        fi
    fi
}

function get_aws_details() {
    local uri="http://169.254.169.254"
    local token
    token=$(${CURL} -s -X PUT "${uri}/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

    local instance_id_uri="${uri}/latest/meta-data/instance-id"
    AWS_INSTANCE_ID=$(${CURL} -H "X-aws-ec2-metadata-token: ${token}" -s ${instance_id_uri})

    local instance_info_uri="${uri}/latest/dynamic/instance-identity/document"
    AWS_ACCOUNT_ID=$(${CURL} -H "X-aws-ec2-metadata-token: ${token}" -s ${instance_info_uri} | grep accountId | awk -F\" '{print $4}')
    AWS_AMI_ID=$(${CURL} -H "X-aws-ec2-metadata-token: ${token}" -s ${instance_info_uri} | grep imageId | awk -F\" '{print $4}')
    AWS_INSTANCE_TYPE=$(${CURL} -H "X-aws-ec2-metadata-token: ${token}" -s ${instance_info_uri} | grep instanceType | awk -F\" '{print $4}')

    # AWS CN detection, as the troubleshooting may differ there
    AWS_AWS_CN="false"
    AWS_REGION=$(${CURL} -H "X-aws-ec2-metadata-token: ${token}" -s ${instance_info_uri} | grep region | awk -F\" '{print $4}')
    if [ ${AWS_REGION} == "ap-northeast-2" ] || [[ ${AWS_REGION} =~ "cn-" ]]; then
        AWS_AWS_CN="true"
    fi
}

function get_os_details() {
    host_architecture=$(uname -p)
    # This might help more
    # shellcheck source=/dev/null
    source /etc/os-release
    host_distro_id="${ID}"
    host_distro_version="${VERSION_ID}"
    host_platform_id="${PLATFORM_ID:-unknown}"
    host_platform="${PRETTY_NAME}"
}

function get_falcon_details() {
    # verify the installed package version
    rpm_version=$(rpm -q falcon-sensor 2>/dev/null)
    rpm_status=$?

    if [ "${rpm_status}" -eq 1 ]; then
        rpm_version=$(alert "package-not-installed")
    else
        rpm_version=$(ok "${rpm_version}")
    fi

    # check the falcon-sensor unit file is enabled
    is_enabled=$(systemctl is-enabled falcon-sensor 2>/dev/null)
    if [ "$?" -eq 1 ]; then
        is_enabled=$(alert "service-not-known")
    fi
    is_failed=$(systemctl is-failed falcon-sensor)

    # check the falcon-sensor is running
    falcon_pid=$(pgrep falcon-sensor | tr "\n" " ")

    # if running, check the version of falcon sensor
    #  - doesn't have to be running, but needs to be installed

    if sudo [ -f "${FALCONCTL}" ]; then
        falcon_version=$(ok "$(sudo ${FALCONCTL} -g --version)")
        # verify the RFM (kernel compatibility) support
        falcon_rfm=$(sudo ${FALCONCTL} -g --rfm-state --rfm-reason)
        # Make it more visible
        if [[ ${falcon_rfm} == *"rfm-state=false"* ]]; then
            falcon_rfm=$(ok "${falcon_rfm}")
            falcon_rfm_check=0
            falcon_kernel_check_info=$(warning "${KERNEL_CHECK_INFO}")
        else
            falcon_rfm=$(alert "${falcon_rfm}")
            falcon_rfm_check=1
            falcon_kernel_check_info=""
        fi
        # check the CID number, and hash the output
        falcon_cid_check_hash=$(sudo ${FALCONCTL} -g --cid | sha256sum | cut -f1 -d\ )
        if [ "${falcon_cid_check_hash}" == "${FALCON_CID_HASH}" ]; then
            falcon_cid_check=$(ok "ok")
        else
            falcon_cid_check=$(alert "mismatching")
        fi
        # Additional checks
        falcon_aid=$(ok "$(sudo ${FALCONCTL} -g --aid | cut -f2 -d= | tr -d '".')")
        falcon_kernel_check=$(sudo bash -c "/opt/CrowdStrike/falcon-kernel-check 2>&1")
        if [ ${falcon_rfm_check} -eq 1 ]; then
            falcon_kernel_check=$(warning "${falcon_kernel_check}")
        fi
        falcon_kernel_modules=$(sudo lsmod | grep -i falcon | cut -f1 -d\  | tr "\n" " ")
    else
        falcon_version=$(alert "not-found")
        falcon_rfm=$(alert "not-found")
        falcon_kernel_check=$(alert "not-found")
        falcon_cid_check=$(alert "not-available")
        falcon_aid=$(alert "not-available")
    fi

    # verify any active connection for falcon-sensor process
    # WARN: On some systems, `netstat` doesn't provide a full process name, so we need to use a shorter one
    if (command -v "ss" >/dev/null 2>&1); then
        falcon_connection=$(sudo ss -tapn | grep falcon-sen | gawk '{ print $5, $1}')
    elif (command -v "netstat" >/dev/null 2>&1); then
        falcon_connection=$(sudo netstat -tapn | grep falcon-sen | gawk '{ print $5, $6}')
    else
        falcon_connection=$(warning "netstat-or-ss-not-present")
        falcon_connection_flag=-1
    fi
    falcon_connection_flag=0
    if [ -z "${falcon_connection}" ]; then
        falcon_connection=$(warning "no-active-connection-found")
        falcon_connection_flag=1
    fi
    # verify whether the DNS resolution works
    dns_resolution_string=$(getent hosts ${FALCON_CLOUD_HOST} | awk '{ print $1 }' | tr '\n' ' ')
    IFS=' ' read -a dns_array <<<"${dns_resolution_string}"
    if [ "${#dns_array[@]}" -eq 0 ]; then
        dns_resolution_test=$(alert "dns-resolution-failed")
        dns_resolution_flag=1
    else
        dns_resolution_test=$(ok "${dns_resolution_string}")
        dns_resolution_flag=0
    fi

    # verify the connection to CS cloud
    falcon_cloud_test=$(${CURL} -s -m 1 ${FALCON_CLOUD_URL} -w "%{http_code}")
    falcon_cloud_test_status=$?

    falcon_cloud_test_flag=0
    # if curl ends up with 28 exit code, it's a timeout
    if [ "${falcon_cloud_test_status}" -eq 28 ]; then
        falcon_cloud_test=$(alert "timeout-error")
        falcon_cloud_test_flag=1
    fi
    # Check if we get "ok200" as a response
    if [ "${falcon_cloud_test}" != "ok200" ]; then
        falcon_cloud_test=$(alert "unexpected-http-response")
        falcon_cloud_test_flag=1
    fi

    # print out the endpoint certificate issuer/subject
    # TODO: Perhaps a few checks could be applied, but I don't have 
    #       solid implementation ideas
    falcon_cloud_ssl_info=$(openssl s_client -connect ${FALCON_CLOUD_HOST}:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -Ei '(Issuer|Subject):')
}

# This function checks for some known weird situations and suggests what could
# be done to improve the situation. It's still rather experimental, though,
# and more feedback is needed to make it better.
function print_suggestions() {
    # Network checks have no errors, yet CS sensor doesn't seem to have active connection.
    if [ "${is_enabled}" == "enabled" ] &&
        [ ${falcon_cloud_test_flag} -eq 0 ] &&
        [ ${dns_resolution_flag} -eq 0 ] &&
        [ ${falcon_connection_flag} -eq 1 ]; then
        echo
        echo "${NETWORK_STATUS_WORKAROUND_INFO}"
    fi
}

get_falcon_details
echo "Falcon Sensor Troubleshooting script"
echo " [*] RPM version: ${rpm_version}"
echo " [*] is unit file enabled: ${is_enabled}"
echo " [*] is unit file active: ${is_failed}"
echo " [*] process ID: ${falcon_pid}"
echo " [*] Falcon AID: ${falcon_aid}"
echo " [*] Falcon CID check: ${falcon_cid_check}"
echo " [*] Falcon runtime version: ${falcon_version}"
echo " [*] Falcon active connection string: ${falcon_connection}"
echo " [*] Falcon DNS resolution test: ${dns_resolution_test}"
echo " [*] Falcon cloud connection test: ${falcon_cloud_test}"
echo " [*] Falcon cloud certificate info:"
echo "${falcon_cloud_ssl_info}"
echo " [*] Falcon kernel modules: ${falcon_kernel_modules}"
echo " [*] Falcon RFM support: ${falcon_rfm}"
echo " [*] Falcon kernel check:"
echo "     ${falcon_kernel_check_info}"
echo "     ${falcon_kernel_check}"

get_os_details
echo
echo "Host Details"
echo " [*] architecture: $(ok "${host_architecture}")"
echo " [*] distribution ID: ${host_distro_id}"
echo " [*] distribution version: ${host_distro_version}"
echo " [*] distro platform ID: ${host_platform_id}"
echo " [*] distro platform name: ${host_platform}"

if [ "$(is_ec2_instance)" == "yes" ]; then
    echo
    echo "AWS Details"
    get_aws_details
    echo " [*] AWS China: ${AWS_AWS_CN}"
    echo " [*] AWS Account: ${AWS_ACCOUNT_ID}"
    echo " [*] AWS EC2 instance ID: ${AWS_INSTANCE_ID}"
    echo " [*] AWS EC2 instance type: ${AWS_INSTANCE_TYPE}"
    echo " [*] AWS AMI ID: ${AWS_AMI_ID}"
    echo " [*] AWS region: ${AWS_REGION}"
else
    echo "AWS Instance: no"
fi

## Print suggestions
print_suggestions

### verify CS Falcon logs
# sudo grep falcon /var/log/messages | tail -n 100
