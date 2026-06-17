.. SPDX-License-Identifier: GPL-2.0

Asynchronous Page Fault Support for arm64
=========================================

KVM/arm64 asynchronous page fault (APF) support lets a guest schedule away
from a task whose vCPU took a stage-2 fault that can be completed by the host
in the background.  The host uses the generic KVM APF worker to fault in the
host page and notifies the guest when the page is not present and when it is
ready.

This support covers the generic KVM APF path.  It does not define a VMM UFFD
ring ABI or any userspace APF event delivery mechanism.  APF is not enabled for
Realm/confidential guests because the control block is ordinary guest memory,
not an explicitly shared page.

Notifications
-------------

The host and guest share one per-vCPU, 64-byte aligned
``struct kvm_vcpu_pv_apf_data`` control block.  The host writes ``reason`` and
``token`` fields, injects a per-vCPU PPI, and waits for the guest to
acknowledge the notification with the APF SMCCC call.  The guest clears the
shared fields before acknowledging the interrupt.

Two notification reasons are defined:

``KVM_PV_REASON_PAGE_NOT_PRESENT``
  The host started an asynchronous fault-in operation.  The token identifies
  the fault.  The guest records the current task against the token and blocks
  it before returning to userspace.

``KVM_PV_REASON_PAGE_READY``
  The host completed an asynchronous fault-in operation.  The guest wakes the
  task associated with the token.  Token ``U32_MAX`` is reserved for the
  wake-all notification used when APF is enabled or restored.

The same PPI carries both notification types.  The default PPI INTID is 17.
Userspace may override it with ``KVM_ARM_VCPU_APF_IRQ`` before APF is enabled
or before an enabled APF state is restored.  APF requires an in-kernel VGIC.
KVM reserves the selected PPI as a VGIC-owned interrupt for the vCPU lifetime;
userspace must not inject it, and APF enable or restore fails if the PPI is
already owned by another in-kernel device or otherwise cannot be reserved.

VCPU device attributes
----------------------

``KVM_ARM_VCPU_APF_CTRL`` exposes per-vCPU APF configuration and migration
state.

``KVM_ARM_VCPU_APF_IRQ``
  Get or set the PPI INTID used for APF notification delivery.  The value must
  be a private peripheral interrupt INTID in the range 16-31.  The attribute
  must be configured before APF is enabled on the vCPU or before an enabled APF
  state is restored.

``KVM_ARM_VCPU_APF_STATE``
  Get or set the APF control-block state for migration.  The value is the same
  64-bit control word passed to ``ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE``: bits
  63-6 hold the 64-byte aligned physical address of the shared control block,
  bit 0 is ``KVM_ASYNC_PF_ENABLED``, and bits 1-5 are reserved and must be zero.
  Any nonzero control word must set ``KVM_ASYNC_PF_ENABLED``.  A zero value
  disables APF.  Restoring an enabled state validates the control block,
  reserves the configured APF PPI, clears transient pending state, and
  sends the guest a wake-all notification so tasks blocked before migration do
  not remain asleep.  Userspace should restore ``KVM_ARM_VCPU_APF_IRQ`` before
  restoring ``KVM_ARM_VCPU_APF_STATE``.

Reset and teardown
------------------

VCPU reset clears the APF enabled state, cached control block, token/GFN
tracking, pending notification state, and queued completions.  The guest must
enable APF again after reset.  The configured APF PPI INTID is userspace
configuration and is not reset by the guest-visible APF enabled state.

Destroying a vCPU drops its queued APF completions and pending APF state; KVM
does not deliver page-ready notifications after vCPU teardown.

SMCCC interface
---------------

The APF interface is advertised through the KVM vendor hypervisor service
bitmap as ``ARM_SMCCC_KVM_FUNC_ASYNC_PF``.  Guests call
``ARM_SMCCC_VENDOR_HYP_KVM_ASYNC_PF_FUNC_ID`` with one of these subfunctions:

``ARM_SMCCC_KVM_FUNC_ASYNC_PF_VERSION``
  Return the APF interface version.

``ARM_SMCCC_KVM_FUNC_ASYNC_PF_SLOTS``
  Return the host APF token capacity for the vCPU.

``ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ``
  Return the PPI INTID used for APF notifications.

``ARM_SMCCC_KVM_FUNC_ASYNC_PF_ENABLE``
  Enable or disable APF on the calling vCPU.  The argument contains the shared
  control-block physical address with APF flags in the low bits.  The address
  must be 64-byte aligned.  ``KVM_ASYNC_PF_ENABLED`` enables APF.  KVM delivers
  page-not-present notifications only for user-mode guest execution.  A nonzero
  argument must set ``KVM_ASYNC_PF_ENABLED``.  Bits 1-5 are reserved and must be
  zero; KVM rejects requests with reserved bits set.

``ARM_SMCCC_KVM_FUNC_ASYNC_PF_IRQ_ACK``
  Acknowledge the current APF PPI notification so KVM can deliver the next one.
