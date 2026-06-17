/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_ASYNC_PF_H__
#define __ARM64_KVM_ASYNC_PF_H__

#include <linux/kvm_types.h>

struct kvm_vcpu;

bool kvm_apf_not_present_allowed(struct kvm_vcpu *vcpu);
bool kvm_apf_gfn_present(struct kvm_vcpu *vcpu, gfn_t gfn);
bool kvm_apf_setup(struct kvm_vcpu *vcpu, gpa_t gpa, gfn_t gfn);

#endif /* __ARM64_KVM_ASYNC_PF_H__ */
