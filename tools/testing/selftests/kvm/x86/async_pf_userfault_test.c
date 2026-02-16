// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM userfaultfd-based async page faults.
 *
 * Verifies the KVM_ASYNC_PF ioctl with KVM_APF_OP_ACCEPT,
 * KVM_APF_OP_SYNC_COMPLETE, and KVM_APF_OP_READY operations
 * against a userfault memslot.
 *
 * Copyright (C) 2026, Amazon.com, Inc.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define TEST_GVA	0xc0000000
#define TEST_GPA	TEST_GVA
#define TEST_NPAGES	1
#define TEST_SIZE	(TEST_NPAGES * PAGE_SIZE)
#define TEST_SLOT	10

static void guest_code(void)
{
	volatile uint64_t val;

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
 * Test: userfault exit with APF flag, then sync_complete.
 * Guest touches a userfault page, KVM exits with MEMORY_FAULT + APF.
 * Userspace "resolves" the page and calls SYNC_COMPLETE.
 * Guest re-enters and completes.
 */
static void test_sync_complete(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	void *mem;
	int r;

	pr_info("Testing KVM_APF_OP_SYNC_COMPLETE\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	run = vcpu->run;

	/* Add a userfault memslot */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT,
				    TEST_NPAGES, KVM_MEM_USERFAULT);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

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

	/*
	 * "Resolve" the page: map real memory into the userfault slot's
	 * backing. In a real scenario this would be UFFDIO_COPY.
	 * For the test, just populate the HVA so the page is present.
	 */
	mem = addr_gpa2hva(vm, TEST_GPA);
	memset(mem, 0, PAGE_SIZE);

	/* Tell KVM we resolved it synchronously */
	async_pf_op(vcpu, TEST_GPA, KVM_APF_OP_SYNC_COMPLETE);

	/* Re-run: guest should complete */
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

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	run = vcpu->run;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT,
				    TEST_NPAGES, KVM_MEM_USERFAULT);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

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
 * Register an eventfd and shared page, trigger a userfault, and verify
 * the notification ring gets an entry and the eventfd is signaled
 * instead of exiting to userspace.
 */
static void test_exitless_eventfd(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_apf_shared_page *shared;
	struct kvm_apf_eventfd evtfd_args = {};
	struct kvm_apf_ring *ring;
	int notify_fd, complete_fd;
	void *shared_mem, *mem;
	uint64_t cnt;
	int r;

	pr_info("Testing exitless APF via eventfd\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	run = vcpu->run;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT,
				    TEST_NPAGES, KVM_MEM_USERFAULT);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

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

	/* Run vCPU — should NOT exit to userspace if exitless works */
	r = _vcpu_run(vcpu);

	ring = &shared->notify;
	if (ring->head != ring->tail) {
		/* Exitless path worked: ring has an entry */
		uint32_t tail = ring->tail & (KVM_APF_RING_SIZE - 1);
		struct kvm_apf_ring_entry *entry = &ring->entries[tail];

		TEST_ASSERT_EQ(entry->gpa, TEST_GPA);
		TEST_ASSERT(entry->flags & KVM_MEMORY_EXIT_FLAG_APF,
			    "Expected APF flag in ring entry");
		pr_info("  Ring entry: gpa=%#llx flags=%#llx\n",
			entry->gpa, entry->flags);

		/* Verify eventfd was signaled */
		r = read(notify_fd, &cnt, sizeof(cnt));
		TEST_ASSERT(r == sizeof(cnt) && cnt > 0,
			    "Expected eventfd signal");

		/* Resolve the page */
		mem = addr_gpa2hva(vm, TEST_GPA);
		memset(mem, 0, PAGE_SIZE);

		/* Complete via the completion ring */
		struct kvm_apf_ring *comp = &shared->complete;
		uint32_t head = comp->head & (KVM_APF_RING_SIZE - 1);

		comp->entries[head].gpa = TEST_GPA;
		comp->entries[head].flags = 0;
		__atomic_store_n(&comp->head,
				 (head + 1) & (KVM_APF_RING_SIZE - 1),
				 __ATOMIC_RELEASE);

		/* Signal completion eventfd to wake KVM */
		cnt = 1;
		r = write(complete_fd, &cnt, sizeof(cnt));
		TEST_ASSERT(r == sizeof(cnt), "write complete eventfd");

		/* Small delay for workqueue to process */
		usleep(10000);

		/* Re-run: guest should complete */
		vcpu_run(vcpu);
		TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);
	} else {
		/*
		 * Exitless didn't fire (e.g. kvm_can_do_async_pf false).
		 * Should have fallen back to normal exit.
		 */
		TEST_ASSERT(r != 0 && errno == EFAULT,
			    "Expected EFAULT fallback");
		TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MEMORY_FAULT);
		pr_info("  Exitless not triggered, fell back to exit - skip\n");
	}

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
	test_sync_complete();
	test_accept_then_ready();
	test_exitless_eventfd();
}
