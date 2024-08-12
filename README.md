# CrowdStrike Falcon Sensor troubleshooting script

This is an initial draft of a collection script that could, eventually,
make troubleshooting of CS Falcon agents easier.

## Requirements

This script relies on `sudo` to be working for the current user. Without it,
the functionality will be reduced and probably not as useful as it could.

## `falcon-kernel-check` tool note

This is from the official documentation:

> Falcon sensor for Linux version 5.38 and later includes a feature to add
> support for new kernels without requiring a sensor update. Support for new
> kernels is added through Zero Touch Linux (ZTL) channel files that are
> deployed to hosts. The `falcon-kernel-check` tool currently only verifies
> kernel support for the initial release of the sensor version. As a result,
> kernel support that has been added through channel files for a sensor version
> are not reflected in the results of the `falcon-kernel-check` tool.

So, for many of the situations when it seems that the latest distro kernel
is NOT supported, it's worth checking that CS sensor can access CrowdStrike
cloud. If so, it will most likely download the latest kernel modules just
for your distribution.

## Possible improvements

- [ ] OS/platform details (distribution, version, architecture, RAM available)
- [ ] runtime metrics (memory consumption, OOM, ...)
- [ ] add the information about `falcon-kernel-tool` to the troubleshooting output
- [ ] reflect the changes CrowdStrike implemented in August 2024, which implements
      full functionality in user (eBPF) mode

## Sample output

If everything goes fine, it should print things like this:

```text
Falcon Sensor Troubleshooting script
 [*] RPM version: falcon-sensor-7.07.0-16206.el9.x86_64
 [*] is unit file enabled: enabled
 [*] is unit file active: active
 [*] process ID: 2338
 [*] Falcon AID: ...
 [*] Falcon CID check: ok
 [*] Falcon runtime version: version = 7.07.16206.0
 [*] Falcon active connection string: 35.162.239.174:443 ESTAB
 [*] Falcon DNS resolution test: 100.20.76.137 35.162.224.228 35.162.239.174
 [*] Falcon cloud connection test: ok200
 [*] Falcon kernel modules: falcon_lsm_serviceable falcon_nf_netcontain falcon_kal
 [*] Falcon RFM support: rfm-state=false, rfm-reason=None, code=0x0.
 [*] Falcon kernel check:
     [!] CS Falcon RFM state is set to false, so the kernel support info may be inaccurate
     Host OS Linux 5.14.0-362.24.1.el9_3.0.1.x86_64 \
     #1 SMP PREEMPT_DYNAMIC Thu Apr 4 22:31:43 UTC 2024 is not supported by Sensor version 16206.

Host Details
 [*] architecture: x86_64
 [*] distribution ID: centos
 [*] distribution version: 7
 [*] distro platform ID: unknown
 [*] distro platform name: CentOS Linux 7 (Core)

AWS Details
 [*] AWS China: false
 [*] AWS Account: ...
 [*] AWS EC2 instance ID: ...
 [*] AWS EC2 instance type: ...
 [*] AWS AMI ID: ...
 [*] AWS region: us-east-1
```

## References

- <https://oit.duke.edu/help/articles/kb0035319/>
