// SPDX-License-Identifier: GPL-2.0-only
/*
 * Asynchronous page fault support for KVM/arm64.
 */

#include <linux/arm-smccc.h>
#include <linux/hash.h>
#include <linux/kvm_host.h>
#include <linux/uaccess.h>
#include <trace/events/kvm.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_para.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_vgic.h>

#include "async_pf.h"

#define KVM_ARM_APF_VERSION	0x010000 /* v1.0.0 */
#define KVM_ARM_APF_IRQ		17

#define KVM_ASYNC_PF_CONTROL_FLAGS	0x3fULL
#define KVM_ASYNC_PF_VALID_FLAGS	KVM_ASYNC_PF_ENABLED

static int apf_read_cached(struct kvm_vcpu *vcpu, u32 offset, u32 *val)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	return kvm_read_guest_offset_cached(vcpu->kvm, &apf->cache,
					    val, offset, sizeof(*val));
}

static int apf_write_cached(struct kvm_vcpu *vcpu, u32 offset, u32 val)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	return kvm_write_guest_offset_cached(vcpu->kvm, &apf->cache,
					     &val, offset, sizeof(val));
}

static u32 kvm_async_pf_hash_fn(gfn_t gfn)
{
	BUILD_BUG_ON(!is_power_of_2(ASYNC_PF_PER_VCPU));

	return hash_32(gfn & 0xffffffff, order_base_2(ASYNC_PF_PER_VCPU));
}

static u32 kvm_async_pf_next_probe(u32 key)
{
	return (key + 1) & (ASYNC_PF_PER_VCPU - 1);
}

static u32 kvm_async_pf_gfn_slot(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	u32 key = kvm_async_pf_hash_fn(gfn);
	int i;

	for (i = 0; i < ASYNC_PF_PER_VCPU &&
	     vcpu->arch.apf->gfns[key] != gfn &&
	     vcpu->arch.apf->gfns[key] != ~0ULL; i++)
		key = kvm_async_pf_next_probe(key);

	return key;
}

bool kvm_apf_gfn_present(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	return apf && apf->gfns[kvm_async_pf_gfn_slot(vcpu, gfn)] == gfn;
}

static void kvm_apf_add_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	u32 key = kvm_async_pf_hash_fn(gfn);

	while (vcpu->arch.apf->gfns[key] != ~0ULL)
		key = kvm_async_pf_next_probe(key);

	vcpu->arch.apf->gfns[key] = gfn;
}

static void kvm_apf_del_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	u32 i, j, k;

	i = j = kvm_async_pf_gfn_slot(vcpu, gfn);
	if (WARN_ON_ONCE(vcpu->arch.apf->gfns[i] != gfn))
		return;

	while (true) {
		vcpu->arch.apf->gfns[i] = ~0ULL;
		do {
			j = kvm_async_pf_next_probe(j);
			if (vcpu->arch.apf->gfns[j] == ~0ULL)
				return;

			k = kvm_async_pf_hash_fn(vcpu->arch.apf->gfns[j]);
		} while ((i <= j) ? (i < k && k <= j) : (i < k || k <= j));

		vcpu->arch.apf->gfns[i] = vcpu->arch.apf->gfns[j];
		i = j;
	}
}

static void kvm_apf_reset_gfns(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ASYNC_PF_PER_VCPU; i++)
		vcpu->arch.apf->gfns[i] = ~0ULL;
}

static int kvm_apf_clear_guest(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = apf_write_cached(vcpu,
			       offsetof(struct kvm_vcpu_pv_apf_data, reason), 0);
	if (ret)
		return ret;

	return apf_write_cached(vcpu,
				offsetof(struct kvm_vcpu_pv_apf_data, token), 0);
}

static void kvm_apf_reset_state(struct kvm_vcpu *vcpu, bool clear_guest)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	if (!apf)
		return;

	if (clear_guest && (apf->control_block & KVM_ASYNC_PF_ENABLED))
		kvm_apf_clear_guest(vcpu);

	kvm_clear_async_pf_completion_queue(vcpu);
	kvm_arch_async_pf_unhalt(vcpu);
	kvm_apf_reset_gfns(vcpu);
	apf->control_block = 0;
	apf->id = 0;
	apf->notpresent_pending = false;
	WRITE_ONCE(apf->pageready_pending, false);

	if (apf->irq_owner)
		kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, false, apf);
}

void kvm_arch_async_pf_reset_vcpu(struct kvm_vcpu *vcpu)
{
	kvm_apf_reset_state(vcpu, false);
}

static u32 kvm_apf_token(struct kvm_vcpu *vcpu)
{
	u32 id = vcpu->arch.apf->id;

	BUILD_BUG_ON(KVM_MAX_VCPUS > (1U << 12));

	/* Bits 0-11 carry the vCPU ID; keep token zero reserved. */

	if ((id << 12) == 0)
		vcpu->arch.apf->id = 1;

	return (vcpu->arch.apf->id++ << 12) | vcpu->vcpu_id;
}

int kvm_arch_async_pf_create_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf;

	apf = kzalloc_obj(*apf, GFP_KERNEL_ACCOUNT);
	if (!apf)
		return -ENOMEM;

	apf->irq = KVM_ARM_APF_IRQ;
	vcpu->arch.apf = apf;
	kvm_apf_reset_gfns(vcpu);

	return 0;
}

void kvm_arch_async_pf_destroy_vcpu(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.apf)
		return;

	kvm_clear_async_pf_completion_queue(vcpu);
	kfree(vcpu->arch.apf);
	vcpu->arch.apf = NULL;
}

static bool kvm_apf_irq_valid(u32 irq)
{
	return irq >= VGIC_NR_SGIS && irq < VGIC_NR_PRIVATE_IRQS;
}

static bool kvm_apf_control_valid(u64 control)
{
	u64 flags = control & KVM_ASYNC_PF_CONTROL_FLAGS;

	if (flags & ~KVM_ASYNC_PF_VALID_FLAGS)
		return false;

	return (flags & KVM_ASYNC_PF_ENABLED) || !control;
}

static int kvm_apf_prepare_irq(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	int ret;

	if (!irqchip_in_kernel(vcpu->kvm))
		return -ENODEV;

	if (!kvm_apf_irq_valid(apf->irq))
		return -EINVAL;

	/*
	 * There is no VGIC clear-owner primitive; pin the PPI for the
	 * vCPU lifetime.
	 */
	if (apf->irq_owner)
		return 0;

	ret = kvm_vgic_set_owner(vcpu, apf->irq, apf);
	if (ret)
		return ret;

	apf->irq_owner = true;
	return 0;
}

static int kvm_apf_set_state(struct kvm_vcpu *vcpu, u64 control,
			     bool update_guest)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	gpa_t gpa = control & ~KVM_ASYNC_PF_CONTROL_FLAGS;
	int ret;

	if (!kvm_apf_control_valid(control))
		return -EINVAL;

	if (!(control & KVM_ASYNC_PF_ENABLED)) {
		kvm_apf_reset_state(vcpu, update_guest);
		return 0;
	}

	ret = kvm_gfn_to_hva_cache_init(vcpu->kvm, &apf->cache, gpa,
					 offsetofend(struct kvm_vcpu_pv_apf_data, token));
	if (ret)
		return ret;

	ret = kvm_apf_prepare_irq(vcpu);
	if (ret)
		return ret;

	kvm_apf_reset_state(vcpu, false);
	apf->control_block = control;
	if (!update_guest)
		return 0;
	ret = kvm_apf_clear_guest(vcpu);
	if (ret) {
		kvm_apf_reset_state(vcpu, false);
		return ret;
	}

	ret = kvm_async_pf_wakeup_all(vcpu);
	if (ret)
		kvm_apf_reset_state(vcpu, true);

	return ret;
}

int kvm_arch_async_pf_set_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	void __user *uaddr = (void __user *)(long)attr->addr;
	u64 control;
	u32 irq;

	if (!apf)
		return -ENXIO;

	switch (attr->attr) {
	case KVM_ARM_VCPU_APF_IRQ:
		if (apf->irq_owner ||
		    apf->control_block & KVM_ASYNC_PF_ENABLED)
			return -EBUSY;
		if (get_user(irq, (u32 __user *)uaddr))
			return -EFAULT;
		if (!kvm_apf_irq_valid(irq))
			return -EINVAL;

		apf->irq = irq;
		return 0;
	case KVM_ARM_VCPU_APF_STATE:
		if (vcpu_has_run_once(vcpu))
			return -EBUSY;
		if (get_user(control, (u64 __user *)uaddr))
			return -EFAULT;

		return kvm_apf_set_state(vcpu, control, false);
	default:
		return -ENXIO;
	}
}

int kvm_arch_async_pf_get_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	void __user *uaddr = (void __user *)(long)attr->addr;

	if (!apf)
		return -ENXIO;

	switch (attr->attr) {
	case KVM_ARM_VCPU_APF_IRQ:
		return put_user(apf->irq, (u32 __user *)uaddr);
	case KVM_ARM_VCPU_APF_STATE:
		return put_user(apf->control_block, (u64 __user *)uaddr);
	default:
		return -ENXIO;
	}
}

int kvm_arch_async_pf_has_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr)
{
	if (!vcpu->arch.apf)
		return -ENXIO;

	switch (attr->attr) {
	case KVM_ARM_VCPU_APF_IRQ:
	case KVM_ARM_VCPU_APF_STATE:
		return 0;
	default:
		return -ENXIO;
	}
}

bool kvm_apf_not_present_allowed(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	u32 reason, token;

	if (!apf || !(apf->control_block & KVM_ASYNC_PF_ENABLED))
		return false;

	if (vcpu_mode_priv(vcpu))
		return false;

	if (!irqchip_in_kernel(vcpu->kvm) ||
	    !kvm_apf_irq_valid(apf->irq) ||
	    !apf->irq_owner)
		return false;
	if (apf->notpresent_pending || READ_ONCE(apf->pageready_pending))
		return false;

	if (apf_read_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason), &reason))
		return false;

	if (apf_read_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token), &token))
		return false;

	return !reason && !token;
}

bool kvm_apf_setup(struct kvm_vcpu *vcpu, gpa_t gpa, gfn_t gfn)
{
	struct kvm_arch_async_pf arch = {
		.token	= kvm_apf_token(vcpu),
		.gfn	= gfn,
	};

	return kvm_setup_async_pf(vcpu, gpa, kvm_vcpu_gfn_to_hva(vcpu, gfn), &arch);
}

bool kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
				     struct kvm_async_pf *work)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	kvm_apf_add_gfn(vcpu, work->arch.gfn);

	if (apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token),
			     work->arch.token))
		goto fail;

	if (apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason),
			     KVM_PV_REASON_PAGE_NOT_PRESENT))
		goto fail;

	apf->notpresent_pending = true;
	trace_kvm_async_pf_not_present(work->arch.token, work->cr2_or_gpa);

	if (kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, true, apf))
		goto fail;

	return true;

fail:
	apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason), 0);
	apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token), 0);
	kvm_apf_del_gfn(vcpu, work->arch.gfn);
	apf->notpresent_pending = false;
	return false;
}

void kvm_arch_async_page_present_queued(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	kvm_make_request(KVM_REQ_ASYNC_PF, vcpu);
	kvm_arch_async_pf_unhalt(vcpu);

	/* Pairs with smp_store_mb() in the page-ready ACK path. */
	smp_mb__after_atomic();

	if (apf && !READ_ONCE(apf->pageready_pending))
		kvm_vcpu_kick(vcpu);
}

void kvm_arch_async_pf_halt(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	if (apf)
		WRITE_ONCE(apf->halted, true);
}

void kvm_arch_async_pf_unhalt(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	kvm_clear_request(KVM_REQ_ASYNC_PF_HALT, vcpu);

	if (!apf || !READ_ONCE(apf->halted))
		return;

	WRITE_ONCE(apf->halted, false);
	kvm_vcpu_wake_up(vcpu);
}

bool kvm_arch_async_pf_is_halted(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;

	return apf && READ_ONCE(apf->halted);
}

bool kvm_arch_can_dequeue_async_page_present(struct kvm_vcpu *vcpu)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	u32 reason, token;

	if (!apf || !(apf->control_block & KVM_ASYNC_PF_ENABLED))
		return true;

	if (apf->notpresent_pending || READ_ONCE(apf->pageready_pending))
		return false;

	if (apf_read_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason), &reason))
		return false;

	if (apf_read_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token), &token))
		return false;

	return !reason && !token;
}

void kvm_arch_async_page_ready(struct kvm_vcpu *vcpu, struct kvm_async_pf *work)
{
	kvm_arch_async_pf_unhalt(vcpu);
}

void kvm_arch_async_page_present(struct kvm_vcpu *vcpu,
				 struct kvm_async_pf *work)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	u32 token = work->arch.token;

	if (work->wakeup_all) {
		token = ~0U;
	} else {
		if (kvm_apf_gfn_present(vcpu, work->arch.gfn))
			kvm_apf_del_gfn(vcpu, work->arch.gfn);

		if (!work->notpresent_injected)
			return;
	}

	if (apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token), token))
		goto clear;

	if (apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason),
			     KVM_PV_REASON_PAGE_READY))
		goto clear;

	trace_kvm_async_pf_ready(token, work->cr2_or_gpa);
	if (kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, true, apf))
		goto clear;

	WRITE_ONCE(apf->pageready_pending, true);
	return;

clear:
	WARN_ON_ONCE(1);
	apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, reason), 0);
	apf_write_cached(vcpu, offsetof(struct kvm_vcpu_pv_apf_data, token), 0);
	WRITE_ONCE(apf->pageready_pending, false);
}

static long kvm_apf_enable(struct kvm_vcpu *vcpu, u64 data)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	int ret;

	if (!apf)
		return SMCCC_RET_NOT_SUPPORTED;

	if (!kvm_apf_control_valid(data))
		return SMCCC_RET_INVALID_PARAMETER;

	if (data == apf->control_block)
		return SMCCC_RET_NOT_REQUIRED;

	ret = kvm_apf_set_state(vcpu, data, true);
	if (!ret)
		return SMCCC_RET_SUCCESS;

	if (ret == -EINVAL)
		return SMCCC_RET_INVALID_PARAMETER;

	return SMCCC_RET_NOT_SUPPORTED;
}

void kvm_arch_async_pf_hypercall(struct kvm_vcpu *vcpu, u64 *val)
{
	struct kvm_arch_async_pf_control *apf = vcpu->arch.apf;
	u32 func = smccc_get_arg1(vcpu);
	u64 data;
	long ret = SMCCC_RET_SUCCESS;

	if (!apf) {
		val[0] = SMCCC_RET_NOT_SUPPORTED;
		return;
	}

	switch (func) {
	case ARM_SMCCC_KVM_FUNC_ASYNC_PF_VERSION:
		val[1] = KVM_ARM_APF_VERSION;
		break;
	case ARM_SMCCC_KVM_FUNC_ASYNC_PF_SLOTS:
		val[1] = ASYNC_PF_PER_VCPU;
		break;
	case ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ:
		val[1] = apf->irq;
		break;
	case ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE:
		data = (u32)smccc_get_arg2(vcpu) |
		       ((u64)(u32)smccc_get_arg3(vcpu) << 32);
		ret = kvm_apf_enable(vcpu, data);
		break;
	case ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ_ACK:
		if (apf->notpresent_pending) {
			apf->notpresent_pending = false;
			kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, false, apf);
			kvm_check_async_pf_completion(vcpu);
		} else if (READ_ONCE(apf->pageready_pending)) {
			smp_store_mb(apf->pageready_pending, false);
			kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, false, apf);
			kvm_check_async_pf_completion(vcpu);
		} else {
			kvm_vgic_inject_irq(vcpu->kvm, vcpu, apf->irq, false, apf);
		}
		break;
	default:
		ret = SMCCC_RET_NOT_SUPPORTED;
	}

	val[0] = ret;
}
