// SPDX-License-Identifier: GPL-2.0
/*
 * KVM asynchronous page fault guest support for arm64.
 */

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/of.h>
#include <linux/percpu.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/swait.h>

#include <asm/kvm_para.h>
#include <asm/rsi.h>

#define KVM_APF_MIN_VERSION	0x010000

#define KVM_TASK_SLEEP_HASHBITS	8
#define KVM_TASK_SLEEP_HASHSIZE	BIT(KVM_TASK_SLEEP_HASHBITS)

struct kvm_task_sleep_node {
	struct hlist_node link;
	struct swait_queue_head wq;
	u32 token;
	int cpu;
	bool dummy;
};

static struct kvm_task_sleep_head {
	raw_spinlock_t lock;
	struct hlist_head list;
} async_pf_sleepers[KVM_TASK_SLEEP_HASHSIZE];

static bool async_pf_available = true;
static DEFINE_PER_CPU_ALIGNED(struct kvm_vcpu_pv_apf_data, apf_data);
static DEFINE_PER_CPU(bool, apf_enabled);
static u32 apf_ppi_intid;
static int apf_irq;

static struct kvm_task_sleep_node *
kvm_async_pf_find_task(struct kvm_task_sleep_head *b, u32 token)
{
	struct hlist_node *p;

	hlist_for_each(p, &b->list) {
		struct kvm_task_sleep_node *n =
			hlist_entry(p, typeof(*n), link);

		if (n->token == token)
			return n;
	}

	return NULL;
}

static bool kvm_async_pf_queue_task(u32 token, struct kvm_task_sleep_node *n)
{
	u32 key = hash_32(token, KVM_TASK_SLEEP_HASHBITS);
	struct kvm_task_sleep_head *b = &async_pf_sleepers[key];
	struct kvm_task_sleep_node *e, *dummy = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&b->lock, flags);
	e = kvm_async_pf_find_task(b, token);
	if (e) {
		/*
		 * A dummy entry means PAGE_READY beat the exit-to-user path to
		 * this token.  Consume the completion and skip sleeping.
		 */
		if (e->dummy) {
			hlist_del(&e->link);
			dummy = e;
		}

		raw_spin_unlock_irqrestore(&b->lock, flags);
		kfree(dummy);
		return false;
	}

	n->token = token;
	n->cpu = smp_processor_id();
	n->dummy = false;
	INIT_HLIST_NODE(&n->link);
	init_swait_queue_head(&n->wq);
	hlist_add_head(&n->link, &b->list);
	raw_spin_unlock_irqrestore(&b->lock, flags);

	return true;
}

static void kvm_async_pf_wake_one(struct kvm_task_sleep_node *n)
{
	hlist_del_init(&n->link);
	if (swq_has_sleeper(&n->wq))
		swake_up_one(&n->wq);
}

static void kvm_async_pf_wake_all(void)
{
	int i, cpu = smp_processor_id();

	for (i = 0; i < KVM_TASK_SLEEP_HASHSIZE; i++) {
		struct kvm_task_sleep_head *b = &async_pf_sleepers[i];
		struct kvm_task_sleep_node *n;
		struct hlist_node *p, *next;
		unsigned long flags;

		raw_spin_lock_irqsave(&b->lock, flags);
		hlist_for_each_safe(p, next, &b->list) {
			n = hlist_entry(p, typeof(*n), link);
			if (n->cpu == cpu)
				kvm_async_pf_wake_one(n);
		}
		raw_spin_unlock_irqrestore(&b->lock, flags);
	}
}

static void kvm_async_pf_task_wake(u32 token)
{
	u32 key = hash_32(token, KVM_TASK_SLEEP_HASHBITS);
	struct kvm_task_sleep_head *b = &async_pf_sleepers[key];
	struct kvm_task_sleep_node *n, *dummy = NULL;
	unsigned long flags;

	if (token == U32_MAX) {
		kvm_async_pf_wake_all();
		return;
	}

again:
	raw_spin_lock_irqsave(&b->lock, flags);
	n = kvm_async_pf_find_task(b, token);
	if (!n) {
		/*
		 * PAGE_READY arrived before the task reached the exit-to-user
		 * wait path.  Remember the completed token so the later wait
		 * consumes it instead of sleeping forever.
		 */
		if (!dummy) {
			raw_spin_unlock_irqrestore(&b->lock, flags);
			dummy = kzalloc_obj(*dummy, GFP_ATOMIC);
			if (!dummy)
				cpu_relax();
			goto again;
		}

		dummy->token = token;
		dummy->cpu = smp_processor_id();
		dummy->dummy = true;
		init_swait_queue_head(&dummy->wq);
		hlist_add_head(&dummy->link, &b->list);
		dummy = NULL;
	} else {
		kvm_async_pf_wake_one(n);
	}
	raw_spin_unlock_irqrestore(&b->lock, flags);

	kfree(dummy);
}

static void kvm_async_pf_set_task_wait(u32 token)
{
	if (WARN_ON_ONCE(test_thread_flag(TIF_ASYNC_PF)))
		return;

	WRITE_ONCE(current->thread.async_pf_token, token);
	set_thread_flag(TIF_ASYNC_PF);
}

void kvm_async_pf_task_wait(void)
{
	struct kvm_task_sleep_node n;
	DECLARE_SWAITQUEUE(wait);
	u32 token = READ_ONCE(current->thread.async_pf_token);

	if (!token) {
		clear_thread_flag(TIF_ASYNC_PF);
		return;
	}

	WRITE_ONCE(current->thread.async_pf_token, 0);
	clear_thread_flag(TIF_ASYNC_PF);

	if (!kvm_async_pf_queue_task(token, &n))
		return;

	for (;;) {
		prepare_to_swait_exclusive(&n.wq, &wait, TASK_UNINTERRUPTIBLE);
		if (hlist_unhashed(&n.link))
			break;

		schedule();
	}
	finish_swait(&n.wq, &wait);
}

static void kvm_async_pf_irq_ack(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
			     ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ_ACK, &res);
}

static irqreturn_t kvm_async_pf_irq_handler(int irq, void *dev_id)
{
	struct pt_regs *regs = get_irq_regs();
	u32 reason = __this_cpu_read(apf_data.reason);
	u32 token = __this_cpu_read(apf_data.token);

	switch (reason) {
	case KVM_PV_REASON_PAGE_NOT_PRESENT:
		if (regs && user_mode(regs))
			kvm_async_pf_set_task_wait(token);
		break;
	case KVM_PV_REASON_PAGE_READY:
		kvm_async_pf_task_wake(token);
		break;
	default:
		pr_warn_once("unexpected async page fault interrupt: reason %u token %#x\n",
			     reason, token);
		break;
	}

	__this_cpu_write(apf_data.reason, 0);
	__this_cpu_write(apf_data.token, 0);
	kvm_async_pf_irq_ack();

	return IRQ_HANDLED;
}

static int __init parse_no_kvmapf(char *arg)
{
	async_pf_available = false;
	return 0;
}
early_param("no-kvmapf", parse_no_kvmapf);

static void kvm_async_pf_disable(void)
{
	struct arm_smccc_res res;

	if (!__this_cpu_read(apf_enabled))
		return;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
			     ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS && res.a0 != SMCCC_RET_NOT_REQUIRED)
		pr_warn("failed to disable async page faults on CPU%d: %ld\n",
			smp_processor_id(), res.a0);

	__this_cpu_write(apf_enabled, false);
}

static void kvm_async_pf_enable(void)
{
	struct arm_smccc_res res;
	u64 control = per_cpu_ptr_to_phys(this_cpu_ptr(&apf_data));

	if (__this_cpu_read(apf_enabled))
		return;

	control |= KVM_ASYNC_PF_ENABLED;
	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
			     ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE,
			     lower_32_bits(control), upper_32_bits(control), &res);
	if (res.a0 != SMCCC_RET_SUCCESS && res.a0 != SMCCC_RET_NOT_REQUIRED) {
		pr_warn("failed to enable async page faults on CPU%d: %ld\n",
			smp_processor_id(), res.a0);
		return;
	}

	__this_cpu_write(apf_enabled, true);
}

static void kvm_async_pf_cpu_disable(void *unused)
{
	disable_percpu_irq(apf_irq);
	kvm_async_pf_disable();
}

static void kvm_async_pf_cpu_enable(void *unused)
{
	enable_percpu_irq(apf_irq, IRQ_TYPE_LEVEL_HIGH);
	kvm_async_pf_enable();
}

static int kvm_async_pf_cpu_online(unsigned int cpu)
{
	kvm_async_pf_cpu_enable(NULL);
	return 0;
}

static int kvm_async_pf_cpu_offline(unsigned int cpu)
{
	kvm_async_pf_cpu_disable(NULL);
	return 0;
}

static int kvm_async_pf_reboot_notify(struct notifier_block *nb,
				      unsigned long code, void *unused)
{
	if (code == SYS_RESTART)
		on_each_cpu(kvm_async_pf_cpu_disable, NULL, 1);

	return NOTIFY_DONE;
}

static struct notifier_block kvm_async_pf_reboot_nb = {
	.notifier_call = kvm_async_pf_reboot_notify,
};

static struct irq_domain *kvm_async_pf_irq_domain(void)
{
	struct irq_domain *domain = irq_get_default_domain();
	struct device_node *np;

	if (domain)
		return domain;

	for_each_node_with_property(np, "interrupt-controller") {
		domain = irq_find_host(np);
		if (domain) {
			of_node_put(np);
			return domain;
		}
	}

	return NULL;
}

static int kvm_async_pf_register_irq(u32 intid)
{
	struct irq_domain *domain = kvm_async_pf_irq_domain();
	struct irq_fwspec fwspec = {};
	unsigned int irq;

	if (!domain)
		return -ENODEV;

	fwspec.fwnode = domain->fwnode;
	if (is_of_node(fwspec.fwnode)) {
		if (intid < 16 || intid > 31)
			return -EINVAL;

		fwspec.param_count = 3;
		fwspec.param[0] = 1;
		fwspec.param[1] = intid - 16;
		fwspec.param[2] = IRQ_TYPE_LEVEL_HIGH;
	} else {
		fwspec.param_count = 2;
		fwspec.param[0] = intid;
		fwspec.param[1] = IRQ_TYPE_LEVEL_HIGH;
	}

	irq = irq_create_fwspec_mapping(&fwspec);
	return irq ?: -EINVAL;
}

static int __init kvm_async_pf_check_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
			     ARM_SMCCC_KVM_FUNC_ASYNC_PF_VERSION, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EOPNOTSUPP;

	if (res.a1 < KVM_APF_MIN_VERSION)
		return -EOPNOTSUPP;

	return 0;
}

static int __init kvm_async_pf_info(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
			     ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EOPNOTSUPP;

	apf_ppi_intid = res.a1;
	return 0;
}

static int __init kvm_async_pf_init(void)
{
	int i, ret;

	if (!async_pf_available || is_realm_world() ||
	    !kvm_para_has_feature(KVM_FEATURE_ASYNC_PF))
		return 0;

	ret = kvm_async_pf_check_version();
	if (ret)
		return ret;

	ret = kvm_async_pf_info();
	if (ret)
		return ret;

	for (i = 0; i < KVM_TASK_SLEEP_HASHSIZE; i++) {
		raw_spin_lock_init(&async_pf_sleepers[i].lock);
		INIT_HLIST_HEAD(&async_pf_sleepers[i].list);
	}

	apf_irq = kvm_async_pf_register_irq(apf_ppi_intid);
	if (apf_irq < 0) {
		ret = apf_irq;
		goto out;
	}

	ret = request_percpu_irq(apf_irq, kvm_async_pf_irq_handler,
				  "KVM async page fault", &apf_data);
	if (ret)
		goto dispose_irq;

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "arm64/kvm-apf:online",
					 kvm_async_pf_cpu_online,
					 kvm_async_pf_cpu_offline);
	if (ret < 0)
		goto free_irq;

	register_reboot_notifier(&kvm_async_pf_reboot_nb);
	on_each_cpu(kvm_async_pf_cpu_enable, NULL, 1);
	pr_info("KVM async page fault enabled, PPI %u\n", apf_ppi_intid);

	return 0;

free_irq:
	free_percpu_irq(apf_irq, &apf_data);
dispose_irq:
	irq_dispose_mapping(apf_irq);
out:
	return ret;
}
fs_initcall(kvm_async_pf_init);
