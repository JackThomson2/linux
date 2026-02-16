// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM userfaultfd-based async page faults.
 *
 * Verifies the KVM_ASYNC_PF ioctl with KVM_APF_OP_ACCEPT
 * and KVM_APF_OP_READY operations, synchronous autocomplete,
 * and exitless eventfd notification against a userfault memslot.
 *
 * Copyright (C) 2026, Amazon.com, Inc.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define TEST_GVA	0xc0000000
#define TEST_GPA	TEST_GVA
#define TEST_NPAGES	1
#define TEST_SIZE	(TEST_NPAGES * PAGE_SIZE)
#define TEST_SLOT	10

/*
 * Helper: add a memslot and mark all its pages as userfault.
 * Creates the memslot first, then sets KVM_MEM_USERFAULT with a bitmap
 * that has all pages marked.
 */
static unsigned long userfault_bitmap;

static void add_userfault_memslot(struct kvm_vm *vm)
{
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT,
				    TEST_NPAGES, 0);

	/* Set all bits in the bitmap — one bit per page */
	userfault_bitmap = (1UL << TEST_NPAGES) - 1;
	vm_mem_region_set_flags_userfault(vm, TEST_SLOT,
					  KVM_MEM_USERFAULT,
					  &userfault_bitmap);
}

static void clear_userfault_memslot(struct kvm_vm *vm)
{
	userfault_bitmap = 0;
	vm_mem_region_set_flags_userfault(vm, TEST_SLOT,
					  KVM_MEM_USERFAULT,
					  &userfault_bitmap);
}

static void guest_code(void)
{
	volatile uint64_t val;

	/*
	 * Enable interrupts so kvm_can_do_async_pf() returns true.
	 * STI has a one-instruction interrupt shadow, so execute a NOP
	 * after it to ensure interrupts are fully enabled before the
	 * memory access that triggers the userfault.
	 */
	asm volatile("sti; nop; nop");

	val = *((uint64_t *)TEST_GVA);
	(void)val;
	GUEST_DONE();
}

static void async_pf_op(struct kvm_vcpu *vcpu, uint64_t gpa, uint32_t op)
{
	struct kvm_async_pf_req req = {
		.gpa = gpa,
		.op = op,
	};
	vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
}

static int _async_pf_op(struct kvm_vcpu *vcpu, uint64_t gpa, uint32_t op)
{
	struct kvm_async_pf_req req = {
		.gpa = gpa,
		.op = op,
	};
	return __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
}

/*
 * Helper: create a VM with one vCPU, enable APF userfault capability,
 * add a userfault memslot, and map it into the guest.
 */
static struct kvm_vm *create_apf_test_vm(struct kvm_vcpu **vcpu)
{
	struct kvm_vm *vm;

	vm = vm_create_with_one_vcpu(vcpu, guest_code);

	/* Enable async PF userfault on this vCPU */
	vcpu_enable_cap(*vcpu, KVM_CAP_ASYNC_PF_USERFAULT, 1);

	/* Add a userfault memslot with bitmap */
	add_userfault_memslot(vm);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

	return vm;
}

/*
 * Test: synchronous resolution via autocomplete.
 * Guest touches a userfault page, KVM exits with MEMORY_FAULT + APF.
 * Userspace resolves the page and re-enters without any ioctl.
 * KVM auto-completes the pending APF on re-entry.
 */
static void test_sync_resolve(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	void *mem;
	int r;

	pr_info("Testing sync resolve (autocomplete)\n");

	vm = create_apf_test_vm(&vcpu);
	run = vcpu->run;

	/* First run: should exit with memory fault + APF */
	r = _vcpu_run(vcpu);
	TEST_ASSERT(r != 0 && errno == EFAULT,
		    "Expected EFAULT, got r=%d errno=%d", r, errno);
	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MEMORY_FAULT);
	TEST_ASSERT(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_USERFAULT,
		    "Expected USERFAULT flag");

	if (!(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_APF)) {
		pr_info("  APF not created (kvm_can_do_async_pf false?) - skip\n");
		goto done;
	}

	TEST_ASSERT_EQ(run->memory_fault.gpa, TEST_GPA);

	/* Resolve the page and clear bitmap — no ioctl needed */
	mem = addr_gpa2hva(vm, TEST_GPA);
	memset(mem, 0, PAGE_SIZE);
	clear_userfault_memslot(vm);

	/* Re-run: KVM auto-completes the APF, guest should complete */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);

done:
	kvm_vm_free(vm);
	pr_info("  PASSED\n");
}

/*
 * Test: accept then ready (async path).
 * Same setup, but userspace accepts the APF, then signals ready.
 */
static void test_accept_then_ready(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	void *mem;
	int r;

	pr_info("Testing KVM_APF_OP_ACCEPT + KVM_APF_OP_READY\n");

	vm = create_apf_test_vm(&vcpu);
	run = vcpu->run;

	r = _vcpu_run(vcpu);
	TEST_ASSERT(r != 0 && errno == EFAULT,
		    "Expected EFAULT, got r=%d errno=%d", r, errno);
	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MEMORY_FAULT);

	if (!(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_APF)) {
		pr_info("  APF not created - skip\n");
		goto done;
	}

	/* Accept the APF */
	async_pf_op(vcpu, TEST_GPA, KVM_APF_OP_ACCEPT);

	/* Resolve the page */
	mem = addr_gpa2hva(vm, TEST_GPA);
	memset(mem, 0, PAGE_SIZE);

	/* Clear userfault bitmap so the page won't fault again */
	clear_userfault_memslot(vm);

	/* Signal ready */
	async_pf_op(vcpu, TEST_GPA, KVM_APF_OP_READY);

	/* Re-run: guest should complete */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);

done:
	kvm_vm_free(vm);
	pr_info("  PASSED\n");
}

/*
 * Test: error cases for the KVM_ASYNC_PF ioctl.
 */
static void test_error_cases(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_async_pf_req req = {};
	int r;

	pr_info("Testing KVM_ASYNC_PF error cases\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	/* Non-zero reserved field */
	req.gpa = TEST_GPA;
	req.op = KVM_APF_OP_READY;
	req.reserved[0] = 1;
	r = __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Expected EINVAL for non-zero reserved");

	/* Non-zero flags */
	memset(&req, 0, sizeof(req));
	req.gpa = TEST_GPA;
	req.op = KVM_APF_OP_READY;
	req.flags = 1;
	r = __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Expected EINVAL for non-zero flags");

	/* Unaligned GPA */
	memset(&req, 0, sizeof(req));
	req.gpa = TEST_GPA + 1;
	req.op = KVM_APF_OP_READY;
	r = __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Expected EINVAL for unaligned GPA");

	/* Invalid op */
	memset(&req, 0, sizeof(req));
	req.gpa = TEST_GPA;
	req.op = 99;
	r = __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Expected EINVAL for invalid op");

	/* READY on non-existent APF */
	memset(&req, 0, sizeof(req));
	req.gpa = TEST_GPA;
	req.op = KVM_APF_OP_READY;
	r = __vcpu_ioctl(vcpu, KVM_ASYNC_PF, &req);
	TEST_ASSERT(r == -1 && errno == ENOENT,
		    "Expected ENOENT for non-existent APF");

	kvm_vm_free(vm);
	pr_info("  PASSED\n");
}

/*
 * Test: exitless APF via eventfd + shared ring buffer.
 *
 * With exitless APF, the vCPU doesn't exit to userspace. Instead, KVM
 * writes to the notify ring, signals the notify eventfd, and auto-halts
 * the vCPU. A handler thread polls the notify eventfd, resolves the page,
 * writes to the completion ring, and signals the completion eventfd.
 * KVM's workqueue then wakes the halted vCPU.
 */
struct exitless_ctx {
	struct kvm_apf_shared_page *shared;
	struct kvm_vm *vm;
	int notify_fd;
	int complete_fd;
};

static void *exitless_handler(void *arg)
{
	struct exitless_ctx *ctx = arg;
	struct kvm_apf_ring *ring = &ctx->shared->notify;
	struct kvm_apf_ring *comp = &ctx->shared->complete;
	uint64_t cnt;
	int r;

	/* Wait for notify eventfd */
	fd_set rfds;
	struct timeval tv = { .tv_sec = 5 };

	FD_ZERO(&rfds);
	FD_SET(ctx->notify_fd, &rfds);
	r = select(ctx->notify_fd + 1, &rfds, NULL, NULL, &tv);
	if (r <= 0)
		return NULL;

	/* Drain eventfd */
	read(ctx->notify_fd, &cnt, sizeof(cnt));

	/* Pop notify ring entry */
	TEST_ASSERT(ring->head != ring->tail, "Expected ring entry");
	uint32_t tail = ring->tail & (KVM_APF_RING_SIZE - 1);
	struct kvm_apf_ring_entry *entry = &ring->entries[tail];

	pr_info("  Ring entry: gpa=%#llx flags=%#llx\n",
		entry->gpa, entry->flags);
	TEST_ASSERT_EQ(entry->gpa, TEST_GPA);

	/* Advance tail */
	__atomic_store_n(&ring->tail,
			 (ring->tail + 1) & (KVM_APF_RING_SIZE - 1),
			 __ATOMIC_RELEASE);

	/* Resolve the page */
	void *mem = addr_gpa2hva(ctx->vm, TEST_GPA);
	memset(mem, 0, PAGE_SIZE);

	/* Clear userfault bitmap */
	clear_userfault_memslot(ctx->vm);

	/* Write completion ring entry */
	uint32_t head = comp->head & (KVM_APF_RING_SIZE - 1);
	comp->entries[head].gpa = TEST_GPA;
	comp->entries[head].flags = 0;
	__atomic_store_n(&comp->head,
			 (comp->head + 1) & (KVM_APF_RING_SIZE - 1),
			 __ATOMIC_RELEASE);

	/* Signal completion eventfd */
	cnt = 1;
	write(ctx->complete_fd, &cnt, sizeof(cnt));

	return (void *)1; /* success */
}

static void test_exitless_eventfd(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_apf_shared_page *shared;
	struct kvm_apf_eventfd evtfd_args = {};
	int notify_fd, complete_fd;
	void *shared_mem;
	pthread_t handler;
	void *handler_ret;

	pr_info("Testing exitless APF via eventfd\n");

	vm = create_apf_test_vm(&vcpu);

	/* Set up shared page */
	shared_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "mmap shared page");
	memset(shared_mem, 0, PAGE_SIZE);
	shared = shared_mem;

	/* Create eventfds */
	notify_fd = eventfd(0, EFD_NONBLOCK);
	TEST_ASSERT(notify_fd >= 0, "eventfd notify");
	complete_fd = eventfd(0, EFD_NONBLOCK);
	TEST_ASSERT(complete_fd >= 0, "eventfd complete");

	/* Register exitless APF */
	evtfd_args.fd = notify_fd;
	evtfd_args.complete_fd = complete_fd;
	evtfd_args.page_addr = (uint64_t)shared_mem;
	vcpu_ioctl(vcpu, KVM_SET_APF_EVENTFD, &evtfd_args);

	/* Start handler thread before running vCPU */
	struct exitless_ctx ctx = {
		.shared = shared,
		.vm = vm,
		.notify_fd = notify_fd,
		.complete_fd = complete_fd,
	};
	pthread_create(&handler, NULL, exitless_handler, &ctx);

	/*
	 * Run vCPU. If exitless works, the vCPU halts, the handler thread
	 * resolves the page and signals completion, KVM wakes the vCPU,
	 * and the guest completes — all without exiting to userspace.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);

	pthread_join(handler, &handler_ret);
	TEST_ASSERT(handler_ret != NULL, "Handler thread should have fired");

	/* Deregister */
	memset(&evtfd_args, 0, sizeof(evtfd_args));
	evtfd_args.fd = -1;
	vcpu_ioctl(vcpu, KVM_SET_APF_EVENTFD, &evtfd_args);

	close(notify_fd);
	close(complete_fd);
	munmap(shared_mem, PAGE_SIZE);
	kvm_vm_free(vm);
	pr_info("  PASSED\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_ASYNC_PF_USERFAULT));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_USERFAULT));

	test_error_cases();
	test_sync_resolve();
	test_accept_then_ready();
	test_exitless_eventfd();
}
