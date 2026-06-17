/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_ARM64_KVM_PARA_H
#define _UAPI_ASM_ARM64_KVM_PARA_H

#include <linux/types.h>

#define KVM_FEATURE_ASYNC_PF		0

#define KVM_ASYNC_PF_ENABLED		(1 << 0)

#define KVM_PV_REASON_PAGE_NOT_PRESENT	1
#define KVM_PV_REASON_PAGE_READY	2

struct kvm_vcpu_pv_apf_data {
	__u32	reason;
	__u32	token;
	__u8	pad[56];
};

#endif /* _UAPI_ASM_ARM64_KVM_PARA_H */
