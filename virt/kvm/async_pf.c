// SPDX-License-Identifier: GPL-2.0-only
/*
 * kvm asynchronous fault support
 *
 * Copyright 2010 Red Hat, Inc.
 *
 * Author:
 *      Gleb Natapov <gleb@redhat.com>
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/circ_buf.h>
#include <linux/mm.h>

#include "async_pf.h"
#include <trace/events/kvm.h>

static struct kmem_cache *async_pf_cache;

int kvm_async_pf_init(void)
{
	async_pf_cache = KMEM_CACHE(kvm_async_pf, 0);

	if (!async_pf_cache)
		return -ENOMEM;

	return 0;
}

void kvm_async_pf_deinit(void)
{
	kmem_cache_destroy(async_pf_cache);
	async_pf_cache = NULL;
}

void kvm_async_pf_vcpu_init(struct kvm_vcpu *vcpu)
{
	INIT_LIST_HEAD(&vcpu->async_pf.done);
	INIT_LIST_HEAD(&vcpu->async_pf.queue);
	spin_lock_init(&vcpu->async_pf.lock);
	atomic_set(&vcpu->async_pf.queued, 0);
	vcpu->async_pf.clearing = false;
	vcpu->async_pf.userfault_enabled = false;
	vcpu->async_pf.eventfd = NULL;
	vcpu->async_pf.complete_eventfd = NULL;
	vcpu->async_pf.pinned_page = NULL;
}

static void async_pf_execute(struct work_struct *work)
{
	struct kvm_async_pf *apf =
		container_of(work, struct kvm_async_pf, work);
	struct kvm_vcpu *vcpu = apf->vcpu;
	struct mm_struct *mm = vcpu->kvm->mm;
	unsigned long addr = apf->addr;
	gpa_t cr2_or_gpa = apf->cr2_or_gpa;
	int locked = 1;
	bool first;

	might_sleep();

	/*
	 * Attempt to pin the VM's host address space, and simply skip gup() if
	 * acquiring a pin fail, i.e. if the process is exiting.  Note, KVM
	 * holds a reference to its associated mm_struct until the very end of
	 * kvm_destroy_vm(), i.e. the struct itself won't be freed before this
	 * work item is fully processed.
	 */
	if (mmget_not_zero(mm)) {
		mmap_read_lock(mm);
		get_user_pages_remote(mm, addr, 1, FOLL_WRITE, NULL, &locked);
		if (locked)
			mmap_read_unlock(mm);
		mmput(mm);
	}

	/*
	 * Notify and kick the vCPU even if faulting in the page failed, e.g.
	 * so that the vCPU can retry the fault synchronously.
	 */
	if (IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC))
		kvm_arch_async_page_present(vcpu, apf);

	spin_lock(&vcpu->async_pf.lock);
	first = list_empty(&vcpu->async_pf.done);
	list_add_tail(&apf->link, &vcpu->async_pf.done);
	spin_unlock(&vcpu->async_pf.lock);

	/*
	 * The apf struct may be freed by kvm_check_async_pf_completion() as
	 * soon as the lock is dropped.  Nullify it to prevent improper usage.
	 */
	apf = NULL;

	if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC) && first)
		kvm_arch_async_page_present_queued(vcpu);

	trace_kvm_async_pf_completed(addr, cr2_or_gpa);

	__kvm_vcpu_wake_up(vcpu);
}

static struct kvm_async_pf *async_pf_find_work_item_from_gfn(struct kvm_vcpu *vcpu,
							     gfn_t gfn)
{
	struct kvm_async_pf *apf;

	lockdep_assert_held(&vcpu->async_pf.lock);

	list_for_each_entry(apf, &vcpu->async_pf.queue, queue) {
		if (apf->arch.gfn == gfn)
			return apf;
	}

	return NULL;
}

int kvm_async_pf_complete(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct kvm_async_pf *apf;
	gfn_t gfn = gpa_to_gfn(gpa);
	unsigned long addr;
	gpa_t cr2_or_gpa;
	bool first;

	spin_lock(&vcpu->async_pf.lock);

	if (unlikely(vcpu->async_pf.clearing)) {
		spin_unlock(&vcpu->async_pf.lock);
		return -EBUSY;
	}

	apf = async_pf_find_work_item_from_gfn(vcpu, gfn);

	if (unlikely(!apf || !apf->userfault)) {
		spin_unlock(&vcpu->async_pf.lock);
		return -ENOENT;
	}

	if (unlikely(apf->uf_state == KVM_APF_UF_COMPLETED)) {
		spin_unlock(&vcpu->async_pf.lock);
		return -EALREADY;
	}

	apf->uf_state = KVM_APF_UF_COMPLETED;

	addr = apf->addr;
	cr2_or_gpa = apf->cr2_or_gpa;

	first = list_empty(&vcpu->async_pf.done);
	list_add_tail(&apf->link, &vcpu->async_pf.done);
	apf = NULL;
	spin_unlock(&vcpu->async_pf.lock);

	if (first)
		kvm_arch_async_page_present_queued(vcpu);

	trace_kvm_async_pf_completed(addr, cr2_or_gpa);

	__kvm_vcpu_wake_up(vcpu);

	return 0;
}

static void kvm_flush_and_free_async_pf_work(struct kvm_async_pf *work)
{
	/*
	 * The async #PF is "done", but KVM must wait for the work item itself,
	 * i.e. async_pf_execute(), to run to completion.  If KVM is a module,
	 * KVM must ensure *no* code owned by the KVM (the module) can be run
	 * after the last call to module_put().  Note, flushing the work item
	 * is always required when the item is taken off the completion queue.
	 * E.g. even if the vCPU handles the item in the "normal" path, the VM
	 * could be terminated before async_pf_execute() completes.
	 *
	 * Wake all events skip the queue and go straight done, i.e. don't
	 * need to be flushed (but sanity check that the work wasn't queued).
	 */
	if (!work->userfault) {
		if (work->wakeup_all)
			WARN_ON_ONCE(work->work.func);
		else
			flush_work(&work->work);
	}
	kmem_cache_free(async_pf_cache, work);
}

bool kvm_async_pf_userfault_exists(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_async_pf *apf;
	bool exists;

	spin_lock(&vcpu->async_pf.lock);
	apf = async_pf_find_work_item_from_gfn(vcpu, gfn);
	exists = apf && apf->userfault;
	spin_unlock(&vcpu->async_pf.lock);

	return exists;
}

int kvm_async_pf_accept(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct kvm_async_pf *apf;
	gfn_t gfn = gpa_to_gfn(gpa);

	spin_lock(&vcpu->async_pf.lock);
	apf = async_pf_find_work_item_from_gfn(vcpu, gfn);

	if (!apf || !apf->userfault) {
		spin_unlock(&vcpu->async_pf.lock);
		return -ENOENT;
	}

	if (apf->uf_state == KVM_APF_UF_PENDING)
		apf->uf_state = KVM_APF_UF_ACCEPTED;

	spin_unlock(&vcpu->async_pf.lock);
	return 0;
}

/*
 * Auto-complete any userfault APFs still in PENDING state.
 *
 * Called on KVM_RUN re-entry. If userspace resolved the page (e.g. via
 * UFFDIO_COPY) and re-enters without calling ACCEPT, auto-complete the
 * APF so the guest retries and finds the page present.
 */
void kvm_async_pf_autocomplete_pending(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *apf;
	bool wakeup = false;

	if (likely(!vcpu->async_pf.userfault_enabled ||
		   !atomic_read(&vcpu->async_pf.queued)))
		return;

	spin_lock(&vcpu->async_pf.lock);
	list_for_each_entry(apf, &vcpu->async_pf.queue, queue) {
		if (apf->userfault && apf->uf_state == KVM_APF_UF_PENDING) {
			apf->uf_state = KVM_APF_UF_COMPLETED;
			list_add_tail(&apf->link, &vcpu->async_pf.done);
			wakeup = true;
		}
	}
	spin_unlock(&vcpu->async_pf.lock);

	if (wakeup)
		kvm_arch_async_page_present_queued(vcpu);
}

static void kvm_apf_teardown_exitless(struct kvm_vcpu *vcpu)
{
	struct eventfd_ctx *old_eventfd, *old_complete;
	struct page *old_page;
	u64 cnt;

	lockdep_assert_held(&vcpu->async_pf.lock);

	old_eventfd = vcpu->async_pf.eventfd;
	old_complete = vcpu->async_pf.complete_eventfd;
	old_page = vcpu->async_pf.pinned_page;

	vcpu->async_pf.eventfd = NULL;
	vcpu->async_pf.complete_eventfd = NULL;
	vcpu->async_pf.pinned_page = NULL;

	spin_unlock(&vcpu->async_pf.lock);

	if (old_complete) {
		eventfd_ctx_remove_wait_queue(old_complete,
					      &vcpu->async_pf.complete_wait,
					      &cnt);
		flush_work(&vcpu->async_pf.complete_work);
		eventfd_ctx_put(old_complete);
	}
	if (old_eventfd)
		eventfd_ctx_put(old_eventfd);
	if (old_page)
		unpin_user_pages(&old_page, 1);

	spin_lock(&vcpu->async_pf.lock);
}

void kvm_clear_async_pf_completion_queue(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->async_pf.lock);
	vcpu->async_pf.clearing = true;

	/* Clean up exitless APF resources */
	if (vcpu->async_pf.eventfd || vcpu->async_pf.complete_eventfd)
		kvm_apf_teardown_exitless(vcpu);

	/* cancel outstanding work queue item */
	while (!list_empty(&vcpu->async_pf.queue)) {
		struct kvm_async_pf *work =
			list_first_entry(&vcpu->async_pf.queue,
					 typeof(*work), queue);
		list_del(&work->queue);

		if (work->userfault) {
			/* Also remove from done list if completed */
			if (work->uf_state == KVM_APF_UF_COMPLETED)
				list_del(&work->link);
			spin_unlock(&vcpu->async_pf.lock);
			kmem_cache_free(async_pf_cache, work);
		} else {
			spin_unlock(&vcpu->async_pf.lock);
#ifdef CONFIG_KVM_ASYNC_PF_SYNC
			flush_work(&work->work);
#else
			if (cancel_work_sync(&work->work))
				kmem_cache_free(async_pf_cache, work);
#endif
		}
		spin_lock(&vcpu->async_pf.lock);
	}

	while (!list_empty(&vcpu->async_pf.done)) {
		struct kvm_async_pf *work =
			list_first_entry(&vcpu->async_pf.done,
					 typeof(*work), link);
		list_del(&work->link);
		spin_unlock(&vcpu->async_pf.lock);
		WARN_ON_ONCE(work->userfault);

		kvm_flush_and_free_async_pf_work(work);
		spin_lock(&vcpu->async_pf.lock);
	}

	atomic_set(&vcpu->async_pf.queued, 0);
	vcpu->async_pf.clearing = false;
	spin_unlock(&vcpu->async_pf.lock);
}

void kvm_check_async_pf_completion(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *work;

	while (!list_empty_careful(&vcpu->async_pf.done) &&
	       kvm_arch_can_dequeue_async_page_present(vcpu)) {
		spin_lock(&vcpu->async_pf.lock);
		if (list_empty(&vcpu->async_pf.done)) {
			spin_unlock(&vcpu->async_pf.lock);
			break;
		}
		work = list_first_entry(&vcpu->async_pf.done, typeof(*work),
					link);
		list_del(&work->link);
		list_del(&work->queue);
		atomic_dec(&vcpu->async_pf.queued);
		spin_unlock(&vcpu->async_pf.lock);

		kvm_arch_async_page_ready(vcpu, work);
		if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC))
			kvm_arch_async_page_present(vcpu, work);

		kvm_flush_and_free_async_pf_work(work);
	}
}

/*
 * Try to schedule a job to handle page fault asynchronously. Returns 'true' on
 * success, 'false' on failure (page fault has to be handled synchronously).
 */
bool kvm_setup_async_pf(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
			unsigned long hva, struct kvm_arch_async_pf *arch,
			bool userfault)
{
	struct kvm_async_pf *work;

	/* Arch specific code should not do async PF in this case */
	if (unlikely(kvm_is_error_hva(hva)))
		return false;

	if (unlikely(atomic_inc_return(&vcpu->async_pf.queued) > ASYNC_PF_PER_VCPU))
		goto failed_setup;

	/*
	 * do alloc nowait since if we are going to sleep anyway we
	 * may as well sleep faulting in page
	 */
	work = kmem_cache_zalloc(async_pf_cache, GFP_NOWAIT | __GFP_NOWARN);
	if (unlikely(!work))
		goto failed_setup;

	work->wakeup_all = false;
	work->vcpu = vcpu;
	work->cr2_or_gpa = cr2_or_gpa;
	work->addr = hva;
	work->arch = *arch;
	work->userfault = userfault;

	spin_lock(&vcpu->async_pf.lock);
	list_add_tail(&work->queue, &vcpu->async_pf.queue);
	spin_unlock(&vcpu->async_pf.lock);

	work->notpresent_injected = kvm_arch_async_page_not_present(vcpu, work);

	if (!userfault) {
		INIT_WORK(&work->work, async_pf_execute);
		schedule_work(&work->work);
	}

	return true;

failed_setup:
	atomic_dec(&vcpu->async_pf.queued);
	return false;
}

int kvm_async_pf_wakeup_all(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *work;
	bool first;

	spin_lock(&vcpu->async_pf.lock);

	if (!list_empty(&vcpu->async_pf.done)) {
		spin_unlock(&vcpu->async_pf.lock);
		return 0;
	}

	work = kmem_cache_zalloc(async_pf_cache, GFP_ATOMIC);
	if (!work) {
		spin_unlock(&vcpu->async_pf.lock);
		return -ENOMEM;
	}

	work->wakeup_all = true;
	INIT_LIST_HEAD(&work->queue); /* for list_del to work */

	first = list_empty(&vcpu->async_pf.done);
	list_add_tail(&work->link, &vcpu->async_pf.done);
	atomic_inc(&vcpu->async_pf.queued);
	spin_unlock(&vcpu->async_pf.lock);

	if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC) && first)
		kvm_arch_async_page_present_queued(vcpu);

	return 0;
}


/*
 * Exitless APF support - signal eventfd instead of exiting to userspace
 */
static void kvm_apf_drain_complete_ring(struct kvm_vcpu *vcpu)
{
	struct kvm_apf_shared_page *shared;
	struct kvm_apf_ring *ring;
	u32 head, tail;

	spin_lock(&vcpu->async_pf.lock);
	if (!vcpu->async_pf.pinned_page) {
		spin_unlock(&vcpu->async_pf.lock);
		return;
	}
	shared = page_address(vcpu->async_pf.pinned_page);
	ring = &shared->complete;
	spin_unlock(&vcpu->async_pf.lock);

	tail = ring->tail & (KVM_APF_RING_SIZE - 1);
	head = smp_load_acquire(&ring->head) & (KVM_APF_RING_SIZE - 1);

	while (CIRC_CNT(head, tail, KVM_APF_RING_SIZE)) {
		struct kvm_apf_ring_entry *entry = &ring->entries[tail];
		gpa_t gpa = entry->gpa;

		tail = (tail + 1) & (KVM_APF_RING_SIZE - 1);
		smp_store_release(&ring->tail, tail);

		kvm_async_pf_complete(vcpu, gpa);

		head = smp_load_acquire(&ring->head) & (KVM_APF_RING_SIZE - 1);
	}
}

static void kvm_apf_complete_work(struct work_struct *work)
{
	struct kvm_vcpu *vcpu = container_of(work, struct kvm_vcpu,
					     async_pf.complete_work);
	kvm_apf_drain_complete_ring(vcpu);
}

static int kvm_apf_complete_wakeup(wait_queue_entry_t *wait, unsigned mode,
				    int sync, void *key)
{
	struct kvm_vcpu *vcpu = container_of(wait, struct kvm_vcpu,
					     async_pf.complete_wait);
	__poll_t flags = key_to_poll(key);

	if (flags & EPOLLIN)
		schedule_work(&vcpu->async_pf.complete_work);

	return 0;
}

struct kvm_apf_complete_pt {
	struct kvm_vcpu *vcpu;
	poll_table pt;
	int ret;
};

static void kvm_apf_complete_register(struct file *file,
				       wait_queue_head_t *wqh,
				       poll_table *pt)
{
	struct kvm_apf_complete_pt *p =
		container_of(pt, struct kvm_apf_complete_pt, pt);
	struct kvm_vcpu *vcpu = p->vcpu;

	init_waitqueue_func_entry(&vcpu->async_pf.complete_wait,
				  kvm_apf_complete_wakeup);
	p->ret = add_wait_queue_priority_exclusive(
		wqh, &vcpu->async_pf.complete_wait);
}

int kvm_apf_set_eventfd(struct kvm_vcpu *vcpu, struct kvm_apf_eventfd *args)
{
	struct eventfd_ctx *eventfd = NULL, *complete_eventfd = NULL;
	struct page *page = NULL;
	struct kvm_apf_complete_pt apf_pt;
	struct fd complete_f = {};
	int ret;

	BUILD_BUG_ON(sizeof(struct kvm_apf_shared_page) > PAGE_SIZE);

	if (args->flags || args->padding)
		return -EINVAL;

	if (args->fd >= 0) {
		if (!args->page_addr || (args->page_addr & ~PAGE_MASK))
			return -EINVAL;

		if (args->fd == args->complete_fd)
			return -EINVAL;

		eventfd = eventfd_ctx_fdget(args->fd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);

		ret = pin_user_pages_fast(args->page_addr, 1,
					  FOLL_WRITE | FOLL_LONGTERM, &page);
		if (ret < 0)
			goto err_eventfd;

		complete_f = fdget(args->complete_fd);
		if (!fd_file(complete_f)) {
			ret = -EBADF;
			goto err_page;
		}
		complete_eventfd = eventfd_ctx_fileget(fd_file(complete_f));
		if (IS_ERR(complete_eventfd)) {
			ret = PTR_ERR(complete_eventfd);
			complete_eventfd = NULL;
			goto err_complete_fd;
		}

		INIT_WORK(&vcpu->async_pf.complete_work,
			  kvm_apf_complete_work);
		apf_pt.vcpu = vcpu;
		init_poll_funcptr(&apf_pt.pt, kvm_apf_complete_register);
		vfs_poll(fd_file(complete_f), &apf_pt.pt);
		ret = apf_pt.ret;
		if (ret)
			goto err_complete_ctx;
	}

	spin_lock(&vcpu->async_pf.lock);

	/* Tear down old exitless resources (drops and re-takes lock) */
	if (vcpu->async_pf.eventfd || vcpu->async_pf.complete_eventfd)
		kvm_apf_teardown_exitless(vcpu);

	vcpu->async_pf.eventfd = eventfd;
	vcpu->async_pf.complete_eventfd = complete_eventfd;
	vcpu->async_pf.pinned_page = page;

	spin_unlock(&vcpu->async_pf.lock);

	if (fd_file(complete_f))
		fdput(complete_f);
	return 0;

err_complete_ctx:
	eventfd_ctx_put(complete_eventfd);
err_complete_fd:
	fdput(complete_f);
err_page:
	unpin_user_pages(&page, 1);
err_eventfd:
	eventfd_ctx_put(eventfd);
	return ret;
}

/*
 * Signal APF via eventfd + ring buffer instead of exiting.
 * Returns true if signaled exitlessly, false if should exit normally.
 */
bool kvm_apf_signal_exitless(struct kvm_vcpu *vcpu, gpa_t gpa, u64 flags)
{
	struct kvm_apf_shared_page *shared;
	struct kvm_apf_ring *ring;
	struct kvm_apf_ring_entry *entry;
	struct eventfd_ctx *eventfd;
	struct kvm_async_pf *apf;
	u32 head, tail;

	spin_lock(&vcpu->async_pf.lock);
	eventfd = vcpu->async_pf.eventfd;
	if (!eventfd || !vcpu->async_pf.pinned_page) {
		spin_unlock(&vcpu->async_pf.lock);
		return false;
	}
	shared = page_address(vcpu->async_pf.pinned_page);
	ring = &shared->notify;

	head = ring->head & (KVM_APF_RING_SIZE - 1);
	tail = smp_load_acquire(&ring->tail) & (KVM_APF_RING_SIZE - 1);

	if (!CIRC_SPACE(head, tail, KVM_APF_RING_SIZE)) {
		spin_unlock(&vcpu->async_pf.lock);
		return false;
	}

	entry = &ring->entries[head];
	entry->gpa = gpa;
	entry->flags = flags;

	smp_store_release(&ring->head, (head + 1) & (KVM_APF_RING_SIZE - 1));

	apf = async_pf_find_work_item_from_gfn(vcpu, gpa_to_gfn(gpa));
	if (apf && apf->userfault && apf->uf_state == KVM_APF_UF_PENDING)
		apf->uf_state = KVM_APF_UF_ACCEPTED;

	spin_unlock(&vcpu->async_pf.lock);

	eventfd_signal(eventfd);

	trace_kvm_apf_exitless_signal(vcpu->vcpu_id, gpa);

	return true;
}
