/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_KVM_PARA_H
#define _ASM_ARM64_KVM_PARA_H

#include <linux/bits.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <uapi/asm/kvm_para.h>

#include <asm/hypervisor.h>

static inline bool kvm_check_and_clear_guest_paused(void)
{
	return false;
}

static inline unsigned int kvm_arch_para_features(void)
{
	unsigned int features = 0;

	if (IS_ENABLED(CONFIG_KVM_GUEST) &&
	    kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_ASYNC_PF))
		features |= BIT(KVM_FEATURE_ASYNC_PF);

	return features;
}

static inline unsigned int kvm_arch_para_hints(void)
{
	return 0;
}

#ifdef CONFIG_KVM_GUEST
static inline bool kvm_para_available(void)
{
	return kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_FEATURES);
}

#else
static inline bool kvm_para_available(void)
{
	return false;
}

#endif

#endif /* _ASM_ARM64_KVM_PARA_H */
