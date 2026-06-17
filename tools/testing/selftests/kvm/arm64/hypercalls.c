// SPDX-License-Identifier: GPL-2.0-only

/* hypercalls: Check the ARM64's psuedo-firmware bitmap register interface.
 *
 * The test validates the basic hypercall functionalities that are exposed
 * via the psuedo-firmware bitmap register. This includes the registers'
 * read/write behavior before and after the VM has started, and if the
 * hypercalls are properly masked or unmasked to the guest when disabled or
 * enabled from the KVM userspace, respectively.
 */
#include <errno.h>
#include <linux/arm-smccc.h>
#include <asm/kvm.h>
#include <asm/kvm_para.h>
#include <kvm_util.h>

#include "gic.h"
#include "processor.h"

#define FW_REG_ULIMIT_VAL(max_feat_bit) (GENMASK(max_feat_bit, 0))

/* Last valid bits of the bitmapped firmware registers */
#define KVM_REG_ARM_STD_BMAP_BIT_MAX		0
#define KVM_REG_ARM_STD_HYP_BMAP_BIT_MAX	0
#define KVM_REG_ARM_VENDOR_HYP_BMAP_BIT_MAX	1
#define KVM_REG_ARM_VENDOR_HYP_BMAP_2_BIT_MAX	2

#define KVM_REG_ARM_STD_BMAP_RESET_VAL		FW_REG_ULIMIT_VAL(KVM_REG_ARM_STD_BMAP_BIT_MAX)
#define KVM_REG_ARM_STD_HYP_BMAP_RESET_VAL	FW_REG_ULIMIT_VAL(KVM_REG_ARM_STD_HYP_BMAP_BIT_MAX)
#define KVM_REG_ARM_VENDOR_HYP_BMAP_RESET_VAL	FW_REG_ULIMIT_VAL(KVM_REG_ARM_VENDOR_HYP_BMAP_BIT_MAX)
#define KVM_REG_ARM_VENDOR_HYP_BMAP_2_RESET_VAL			\
	BIT(KVM_REG_ARM_VENDOR_HYP_BIT_ASYNC_PF)

#define ST_GPA_BASE		BIT_ULL(30)
#define APF_GPA_BASE		(ST_GPA_BASE + 0x10000)
#define APF_DATA_SIZE		64
#define APF_TEST_IRQ		(MIN_SPI - 1)
#define APF_CONTROL_BLOCK	(APF_GPA_BASE | BIT_ULL(0))
#define APF_ALT_CONTROL_BLOCK	((APF_GPA_BASE + APF_DATA_SIZE) | BIT_ULL(0))
#define APF_RESERVED_FLAGS	BIT_ULL(1)
#define KVM_APF_MIN_VERSION	0x010000

struct kvm_fw_reg_info {
	u64 reg;		/* Register definition */
	u64 max_feat_bit;	/* Bit that represents the upper limit of the feature-map */
	u64 reset_val;	/* Reset value for the register */
};

#define FW_REG_INFO(r)			\
	{					\
		.reg = r,			\
		.max_feat_bit = r##_BIT_MAX,	\
		.reset_val = r##_RESET_VAL	\
	}

static const struct kvm_fw_reg_info fw_reg_info[] = {
	FW_REG_INFO(KVM_REG_ARM_STD_BMAP),
	FW_REG_INFO(KVM_REG_ARM_STD_HYP_BMAP),
	FW_REG_INFO(KVM_REG_ARM_VENDOR_HYP_BMAP),
	FW_REG_INFO(KVM_REG_ARM_VENDOR_HYP_BMAP_2),
};

enum test_stage {
	TEST_STAGE_REG_IFACE,
	TEST_STAGE_HVC_IFACE_FEAT_DISABLED,
	TEST_STAGE_HVC_IFACE_FEAT_ENABLED,
	TEST_STAGE_HVC_IFACE_FALSE_INFO,
	TEST_STAGE_APF_INFO,
	TEST_STAGE_APF_INVALID_FLAGS,
	TEST_STAGE_APF_ENABLED,
	TEST_STAGE_END,
};

static int stage = TEST_STAGE_REG_IFACE;

struct test_hvc_info {
	u32 func_id;
	u64 arg1;
};

#define TEST_HVC_INFO(f, a1)	\
	{			\
		.func_id = f,	\
		.arg1 = a1,	\
	}

static const struct test_hvc_info hvc_info[] = {
	/* KVM_REG_ARM_STD_BMAP */
	TEST_HVC_INFO(ARM_SMCCC_TRNG_VERSION, 0),
	TEST_HVC_INFO(ARM_SMCCC_TRNG_FEATURES, ARM_SMCCC_TRNG_RND64),
	TEST_HVC_INFO(ARM_SMCCC_TRNG_GET_UUID, 0),
	TEST_HVC_INFO(ARM_SMCCC_TRNG_RND32, 0),
	TEST_HVC_INFO(ARM_SMCCC_TRNG_RND64, 0),

	/* KVM_REG_ARM_STD_HYP_BMAP */
	TEST_HVC_INFO(ARM_SMCCC_ARCH_FEATURES_FUNC_ID, ARM_SMCCC_HV_PV_TIME_FEATURES),
	TEST_HVC_INFO(ARM_SMCCC_HV_PV_TIME_FEATURES, ARM_SMCCC_HV_PV_TIME_ST),
	TEST_HVC_INFO(ARM_SMCCC_HV_PV_TIME_ST, 0),

	/* KVM_REG_ARM_VENDOR_HYP_BMAP */
	TEST_HVC_INFO(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID,
			ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID),
	TEST_HVC_INFO(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, 0),
	TEST_HVC_INFO(ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID, KVM_PTP_VIRT_COUNTER),

	/* KVM_REG_ARM_VENDOR_HYP_BMAP_2 */
	TEST_HVC_INFO(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
		      ARM_SMCCC_KVM_FUNC_ASYNC_PF_VERSION),
};

/* Feed false hypercall info to test the KVM behavior */
static const struct test_hvc_info false_hvc_info[] = {
	/* Feature support check against a different family of hypercalls */
	TEST_HVC_INFO(ARM_SMCCC_TRNG_FEATURES, ARM_SMCCC_VENDOR_HYP_KVM_PTP_FUNC_ID),
	TEST_HVC_INFO(ARM_SMCCC_ARCH_FEATURES_FUNC_ID, ARM_SMCCC_TRNG_RND64),
	TEST_HVC_INFO(ARM_SMCCC_HV_PV_TIME_FEATURES, ARM_SMCCC_TRNG_RND64),
};

static void guest_test_hvc(const struct test_hvc_info *hc_info)
{
	unsigned int i;
	struct arm_smccc_res res;
	unsigned int hvc_info_arr_sz;

	hvc_info_arr_sz =
	hc_info == hvc_info ? ARRAY_SIZE(hvc_info) : ARRAY_SIZE(false_hvc_info);

	for (i = 0; i < hvc_info_arr_sz; i++, hc_info++) {
		memset(&res, 0, sizeof(res));
		do_smccc(hc_info->func_id, hc_info->arg1, 0, 0, 0, 0, 0, 0, &res);

		switch (stage) {
		case TEST_STAGE_HVC_IFACE_FEAT_DISABLED:
		case TEST_STAGE_HVC_IFACE_FALSE_INFO:
			__GUEST_ASSERT(res.a0 == SMCCC_RET_NOT_SUPPORTED,
				       "a0 = 0x%lx, func_id = 0x%x, arg1 = 0x%lx, stage = %u",
					res.a0, hc_info->func_id, hc_info->arg1, stage);
			break;
		case TEST_STAGE_HVC_IFACE_FEAT_ENABLED:
			__GUEST_ASSERT(res.a0 != SMCCC_RET_NOT_SUPPORTED,
				       "a0 = 0x%lx, func_id = 0x%x, arg1 = 0x%lx, stage = %u",
					res.a0, hc_info->func_id, hc_info->arg1, stage);
			break;
		default:
			GUEST_FAIL("Unexpected stage = %u", stage);
		}
	}
}

static void guest_async_pf_call(u32 func, struct arm_smccc_res *res)
{
	memset(res, 0, sizeof(*res));
	do_smccc(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
		 func, 0, 0, 0, 0, 0, 0, res);
}

static void guest_test_async_pf_info(void)
{
	struct arm_smccc_res res;

	memset(&res, 0, sizeof(res));
	do_smccc(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID,
		 0, 0, 0, 0, 0, 0, 0, &res);
	__GUEST_ASSERT(res.a2 & BIT(KVM_REG_ARM_VENDOR_HYP_BIT_ASYNC_PF),
		       "APF missing from vendor-hyp features: a2 = 0x%lx",
		       res.a2);

	guest_async_pf_call(ARM_SMCCC_KVM_FUNC_ASYNC_PF_VERSION, &res);
	__GUEST_ASSERT(res.a0 == SMCCC_RET_SUCCESS && res.a1 >= KVM_APF_MIN_VERSION,
		       "Unexpected APF version response: a0 = 0x%lx, a1 = 0x%lx",
		       res.a0, res.a1);

	guest_async_pf_call(ARM_SMCCC_KVM_FUNC_ASYNC_PF_SLOTS, &res);
	__GUEST_ASSERT(res.a0 == SMCCC_RET_SUCCESS && res.a1,
		       "Unexpected APF slots response: a0 = 0x%lx, a1 = 0x%lx",
		       res.a0, res.a1);

	guest_async_pf_call(ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ, &res);
	__GUEST_ASSERT(res.a0 == SMCCC_RET_SUCCESS && res.a1 == APF_TEST_IRQ,
		       "Unexpected APF IRQ response: a0 = 0x%lx, a1 = 0x%lx",
		       res.a0, res.a1);

	guest_async_pf_call(~0U, &res);
	__GUEST_ASSERT(res.a0 == SMCCC_RET_NOT_SUPPORTED,
		       "APF accepted unknown function: a0 = 0x%lx", res.a0);
}

static unsigned long guest_async_pf_enable(u64 data)
{
	struct arm_smccc_res res;

	memset(&res, 0, sizeof(res));
	do_smccc(ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID,
		 ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE,
		 (u32)data, data >> 32, 0, 0, 0, 0, &res);

	return res.a0;
}

static void guest_test_async_pf_invalid_flags(void)
{
	unsigned long ret;

	ret = guest_async_pf_enable(APF_RESERVED_FLAGS);
	__GUEST_ASSERT(ret == SMCCC_RET_INVALID_PARAMETER,
		       "APF accepted reserved disable flags: a0 = 0x%lx", ret);

	ret = guest_async_pf_enable(APF_CONTROL_BLOCK | APF_RESERVED_FLAGS);
	__GUEST_ASSERT(ret == SMCCC_RET_INVALID_PARAMETER,
		       "APF accepted reserved enable flags: a0 = 0x%lx", ret);

	ret = guest_async_pf_enable(APF_GPA_BASE);
	__GUEST_ASSERT(ret == SMCCC_RET_INVALID_PARAMETER,
		       "APF accepted nonzero block without enable: a0 = 0x%lx",
		       ret);
}

static void guest_enable_async_pf(void)
{
	unsigned long ret;

	ret = guest_async_pf_enable(APF_CONTROL_BLOCK);
	__GUEST_ASSERT(ret == SMCCC_RET_SUCCESS,
		       "Failed to enable APF: a0 = 0x%lx", ret);

	ret = guest_async_pf_enable(APF_ALT_CONTROL_BLOCK);
	__GUEST_ASSERT(ret == SMCCC_RET_SUCCESS,
		       "Failed to repoint APF block: a0 = 0x%lx", ret);

	ret = guest_async_pf_enable(APF_ALT_CONTROL_BLOCK);
	__GUEST_ASSERT(ret == SMCCC_RET_NOT_REQUIRED,
		       "APF exact re-enable was not a no-op: a0 = 0x%lx", ret);

	ret = guest_async_pf_enable(APF_CONTROL_BLOCK);
	__GUEST_ASSERT(ret == SMCCC_RET_SUCCESS,
		       "Failed to restore APF block: a0 = 0x%lx", ret);
}

static void guest_code(void)
{
	while (stage != TEST_STAGE_END) {
		switch (stage) {
		case TEST_STAGE_REG_IFACE:
			break;
		case TEST_STAGE_HVC_IFACE_FEAT_DISABLED:
		case TEST_STAGE_HVC_IFACE_FEAT_ENABLED:
			guest_test_hvc(hvc_info);
			break;
		case TEST_STAGE_HVC_IFACE_FALSE_INFO:
			guest_test_hvc(false_hvc_info);
			break;
		case TEST_STAGE_APF_INFO:
			guest_test_async_pf_info();
			break;
		case TEST_STAGE_APF_INVALID_FLAGS:
			guest_test_async_pf_invalid_flags();
			break;
		case TEST_STAGE_APF_ENABLED:
			guest_enable_async_pf();
			break;
		default:
			GUEST_FAIL("Unexpected stage = %u", stage);
		}

		GUEST_SYNC(stage);
	}

	GUEST_DONE();
}

struct st_time {
	u32 rev;
	u32 attr;
	u64 st_time;
};

#define STEAL_TIME_SIZE		((sizeof(struct st_time) + 63) & ~63)

static void steal_time_init(struct kvm_vcpu *vcpu)
{
	u64 st_ipa = (ulong)ST_GPA_BASE;
	unsigned int gpages;

	gpages = vm_calc_num_guest_pages(VM_MODE_DEFAULT, STEAL_TIME_SIZE);
	vm_userspace_mem_region_add(vcpu->vm, VM_MEM_SRC_ANONYMOUS, ST_GPA_BASE, 1, gpages, 0);

	vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_PVTIME_CTRL,
			     KVM_ARM_VCPU_PVTIME_IPA, &st_ipa);
}

static void async_pf_init(struct kvm_vcpu *vcpu)
{
	unsigned int gpages;

	gpages = vm_calc_num_guest_pages(VM_MODE_DEFAULT, APF_DATA_SIZE);
	vm_userspace_mem_region_add(vcpu->vm, VM_MEM_SRC_ANONYMOUS,
				    APF_GPA_BASE, 2, gpages, 0);
}

static void test_apf_state_attr_before_vm_start(struct kvm_vcpu *vcpu)
{
	u64 state = ~0ULL;
	int ret;

	ret = __vcpu_has_device_attr(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_STATE);
	TEST_ASSERT(!ret, "APF state attr missing: ret = %d, errno = %d",
		    ret, errno);

	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(!state, "APF state reset value is not zero: 0x%lx", state);

	state = APF_RESERVED_FLAGS;
	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(ret && errno == EINVAL,
		    "APF state accepted reserved disable flags: ret = %d, errno = %d",
		    ret, errno);

	state = APF_CONTROL_BLOCK | APF_RESERVED_FLAGS;
	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(ret && errno == EINVAL,
		    "APF state accepted reserved enable flags: ret = %d, errno = %d",
		    ret, errno);

	state = APF_GPA_BASE;
	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(ret && errno == EINVAL,
		    "APF state accepted nonzero block without enable: ret = %d, errno = %d",
		    ret, errno);

	state = APF_CONTROL_BLOCK;
	vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(state == APF_CONTROL_BLOCK,
		    "APF state readback mismatch: 0x%lx", state);

	state = 0;
	vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(!state, "APF state disable readback mismatch: 0x%lx",
		    state);
}

static void test_apf_irq_attr_before_enable(struct kvm_vcpu *vcpu)
{
	u32 irq = 0;
	int ret;

	ret = __vcpu_has_device_attr(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_IRQ);
	TEST_ASSERT(!ret, "APF IRQ attr missing: ret = %d, errno = %d",
		    ret, errno);

	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(irq >= MIN_PPI && irq < MIN_SPI,
		    "APF IRQ default is not a PPI: %u", irq);

	irq = MIN_PPI - 1;
	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(ret && errno == EINVAL,
		    "APF IRQ accepted SGI %u: ret = %d, errno = %d",
		    irq, ret, errno);

	irq = MIN_SPI;
	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(ret && errno == EINVAL,
		    "APF IRQ accepted SPI %u: ret = %d, errno = %d",
		    irq, ret, errno);

	irq = MIN_PPI;
	vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_IRQ, &irq);
	irq = 0;
	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(irq == MIN_PPI, "APF IRQ lower-bound readback mismatch: %u",
		    irq);

	irq = APF_TEST_IRQ;
	vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_IRQ, &irq);

	irq = 0;
	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(irq == APF_TEST_IRQ, "APF IRQ readback mismatch: %u", irq);
}

static void test_apf_irq_attr_after_enable(struct kvm_vcpu *vcpu)
{
	u64 state = 0;
	u32 irq = APF_TEST_IRQ;
	int ret;

	ret = __vcpu_device_attr_set(vcpu, KVM_ARM_VCPU_APF_CTRL,
				     KVM_ARM_VCPU_APF_IRQ, &irq);
	TEST_ASSERT(ret && errno == EBUSY,
		    "APF IRQ changed after enable: ret = %d, errno = %d",
		    ret, errno);

	vcpu_device_attr_get(vcpu, KVM_ARM_VCPU_APF_CTRL,
			     KVM_ARM_VCPU_APF_STATE, &state);
	TEST_ASSERT(state == APF_CONTROL_BLOCK,
		    "APF state readback mismatch: 0x%lx", state);
}

static void test_fw_regs_before_vm_start(struct kvm_vcpu *vcpu)
{
	u64 val;
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(fw_reg_info); i++) {
		const struct kvm_fw_reg_info *reg_info = &fw_reg_info[i];
		u64 set_val;

		/* First 'read' should be the reset value for the reg  */
		val = vcpu_get_reg(vcpu, reg_info->reg);
		TEST_ASSERT(val == reg_info->reset_val,
			"Unexpected reset value for reg: 0x%lx; expected: 0x%lx; read: 0x%lx",
			reg_info->reg, reg_info->reset_val, val);

		if (reg_info->reset_val)
			set_val = 0;
		else
			set_val = FW_REG_ULIMIT_VAL(reg_info->max_feat_bit);

		ret = __vcpu_set_reg(vcpu, reg_info->reg, set_val);
		TEST_ASSERT(ret == 0,
			"Failed to %s all the features of reg: 0x%lx; ret: %d",
			(set_val ? "set" : "clear"), reg_info->reg, errno);

		val = vcpu_get_reg(vcpu, reg_info->reg);
		TEST_ASSERT(val == set_val,
			"Expected all the features to be %s for reg: 0x%lx",
			(set_val ? "set" : "cleared"), reg_info->reg);

		/*
		 * If the reg has been set, clear it as test_fw_regs_after_vm_start()
		 * expects it to be cleared.
		 */
		if (set_val) {
			ret = __vcpu_set_reg(vcpu, reg_info->reg, 0);
			TEST_ASSERT(ret == 0,
			"Failed to clear all the features of reg: 0x%lx; ret: %d",
			reg_info->reg, errno);
		}

		/*
		 * Test enabling a feature that's not supported.
		 * Avoid this check if all the bits are occupied.
		 */
		if (reg_info->max_feat_bit < 63) {
			ret = __vcpu_set_reg(vcpu, reg_info->reg, BIT(reg_info->max_feat_bit + 1));
			TEST_ASSERT(ret != 0 && errno == EINVAL,
			"Unexpected behavior or return value (%d) while setting an unsupported feature for reg: 0x%lx",
			errno, reg_info->reg);
		}
	}
}

static void test_fw_regs_after_vm_start(struct kvm_vcpu *vcpu)
{
	u64 val;
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(fw_reg_info); i++) {
		const struct kvm_fw_reg_info *reg_info = &fw_reg_info[i];

		/*
		 * Before starting the VM, the test clears all the bits.
		 * Check if that's still the case.
		 */
		val = vcpu_get_reg(vcpu, reg_info->reg);
		TEST_ASSERT(val == 0,
			"Expected all the features to be cleared for reg: 0x%lx",
			reg_info->reg);

		/*
		 * Since the VM has run at least once, KVM shouldn't allow modification of
		 * the registers and should return EBUSY. Set the registers and check for
		 * the expected errno.
		 */
		ret = __vcpu_set_reg(vcpu, reg_info->reg, FW_REG_ULIMIT_VAL(reg_info->max_feat_bit));
		TEST_ASSERT(ret != 0 && errno == EBUSY,
		"Unexpected behavior or return value (%d) while setting a feature while VM is running for reg: 0x%lx",
		errno, reg_info->reg);
	}
}

static struct kvm_vm *test_vm_create(struct kvm_vcpu **vcpu)
{
	struct kvm_vm *vm;

	vm = vm_create_with_one_vcpu(vcpu, guest_code);

	steal_time_init(*vcpu);
	async_pf_init(*vcpu);
	test_apf_irq_attr_before_enable(*vcpu);
	test_apf_state_attr_before_vm_start(*vcpu);

	return vm;
}

static void test_guest_stage(struct kvm_vm **vm, struct kvm_vcpu **vcpu)
{
	int prev_stage = stage;

	pr_debug("Stage: %d\n", prev_stage);

	/* Sync the stage early, the VM might be freed below. */
	stage++;
	sync_global_to_guest(*vm, stage);

	switch (prev_stage) {
	case TEST_STAGE_REG_IFACE:
		test_fw_regs_after_vm_start(*vcpu);
		break;
	case TEST_STAGE_HVC_IFACE_FEAT_DISABLED:
		/* Start a new VM so default-enabled firmware features are exposed. */
		kvm_vm_free(*vm);
		*vm = test_vm_create(vcpu);
		break;
	case TEST_STAGE_HVC_IFACE_FEAT_ENABLED:
	case TEST_STAGE_HVC_IFACE_FALSE_INFO:
	case TEST_STAGE_APF_INFO:
	case TEST_STAGE_APF_INVALID_FLAGS:
		break;
	case TEST_STAGE_APF_ENABLED:
		test_apf_irq_attr_after_enable(*vcpu);
		break;
	default:
		TEST_FAIL("Unknown test stage: %d", prev_stage);
	}
}

static void test_run(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	bool guest_done = false;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ASYNC_PF));
	TEST_ASSERT(!kvm_has_cap(KVM_CAP_ASYNC_PF_INT),
		    "arm64 unexpectedly advertises KVM_CAP_ASYNC_PF_INT");

	vm = test_vm_create(&vcpu);

	test_fw_regs_before_vm_start(vcpu);

	while (!guest_done) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			test_guest_stage(&vm, &vcpu);
			break;
		case UCALL_DONE:
			guest_done = true;
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		default:
			TEST_FAIL("Unexpected guest exit");
		}
	}

	kvm_vm_free(vm);
}

int main(void)
{
	test_run();
	return 0;
}
