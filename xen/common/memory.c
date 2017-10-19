/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/errno.h>
#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#include <xen/numa.h>
#include <xen/mem_access.h>
#include <xen/trace.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <asm/p2m.h>
#include <public/memory.h>
#include <xsm/xsm.h>

struct memop_args {
    /* INPUT */
    struct domain *domain;     /* Domain to be affected. */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_list; /* List of extent base addrs. */
    unsigned int nr_extents;   /* Number of extents to allocate or free. */
    unsigned int extent_order; /* Size of each extent. */
    unsigned int memflags;     /* Allocation flags. */

    /* INPUT/OUTPUT */
    unsigned int nr_done;    /* Number of extents processed so far. */
    int          preempted;  /* Was the hypercall preempted? */
};

#ifndef CONFIG_CTLDOM_MAX_ORDER
#define CONFIG_CTLDOM_MAX_ORDER CONFIG_PAGEALLOC_MAX_ORDER
#endif
#ifndef CONFIG_PTDOM_MAX_ORDER
#define CONFIG_PTDOM_MAX_ORDER CONFIG_HWDOM_MAX_ORDER
#endif

static unsigned int __read_mostly domu_max_order = CONFIG_DOMU_MAX_ORDER;
static unsigned int __read_mostly ctldom_max_order = CONFIG_CTLDOM_MAX_ORDER;
static unsigned int __read_mostly hwdom_max_order = CONFIG_HWDOM_MAX_ORDER;
#ifdef HAS_PASSTHROUGH
static unsigned int __read_mostly ptdom_max_order = CONFIG_PTDOM_MAX_ORDER;
#endif

static int __init parse_max_order(const char *s)
{
    if ( *s != ',' )
        domu_max_order = simple_strtoul(s, &s, 0);
    if ( *s == ',' && *++s != ',' )
        ctldom_max_order = simple_strtoul(s, &s, 0);
    if ( *s == ',' && *++s != ',' )
        hwdom_max_order = simple_strtoul(s, &s, 0);
#ifdef HAS_PASSTHROUGH
    if ( *s == ',' && *++s != ',' )
        ptdom_max_order = simple_strtoul(s, &s, 0);
#endif

    return *s ? -EINVAL : 0;
}
custom_param("memop-max-order", parse_max_order);

static unsigned int max_order(const struct domain *d)
{
    unsigned int order = domu_max_order;

#ifdef HAS_PASSTHROUGH
    if ( cache_flush_permitted(d) && order < ptdom_max_order )
        order = ptdom_max_order;
#endif

    if ( is_control_domain(d) && order < ctldom_max_order )
        order = ctldom_max_order;

    if ( is_hardware_domain(d) && order < hwdom_max_order )
        order = hwdom_max_order;

    return min(order, MAX_ORDER + 0U);
}

static void increase_reservation(struct memop_args *a)
{
    struct page_info *page;
    unsigned long i;
    xen_pfn_t mfn;
    struct domain *d = a->domain;

    if ( !guest_handle_is_null(a->extent_list) &&
         !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( a->extent_order > max_order(current->domain) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( i != a->nr_done && hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        page = alloc_domheap_pages(d, a->extent_order, a->memflags);
        if ( unlikely(page == NULL) ) 
        {
            gdprintk(XENLOG_INFO, "Could not allocate order=%d extent: "
                    "id=%d memflags=%x (%ld of %d)\n",
                     a->extent_order, d->domain_id, a->memflags,
                     i, a->nr_extents);
            goto out;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( !paging_mode_translate(d) &&
             !guest_handle_is_null(a->extent_list) )
        {
            mfn = page_to_mfn(page);
            if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                goto out;
        }
    }

 out:
    a->nr_done = i;
}

#ifdef XEN_NUMA_POLICY
int dom_memalloc_max_order = PAGE_ORDER_1G;
#endif

static void populate_physmap(struct memop_args *a)
{
    struct page_info *page;
    unsigned int i, j;
    xen_pfn_t gpfn, mfn;
    struct domain *d = a->domain, *curr_d = current->domain;
    bool need_tlbflush = false;
    uint32_t tlbflush_timestamp = 0;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) )
        return;

    if ( a->extent_order > (a->memflags & MEMF_populate_on_demand ? MAX_ORDER :
                            max_order(curr_d)) )
        return;

    if ( unlikely(!d->creation_finished) )
    {
        /*
         * With MEMF_no_tlbflush set, alloc_heap_pages() will ignore
         * TLB-flushes. After VM creation, this is a security issue (it can
         * make pages accessible to guest B, when guest A may still have a
         * cached mapping to them). So we do this only during domain creation,
         * when the domain itself has not yet been unpaused for the first
         * time.
         */
        a->memflags |= MEMF_no_tlbflush;
        /*
         * With MEMF_no_icache_flush, alloc_heap_pages() will skip
         * performing icache flushes. We do it only before domain
         * creation as once the domain is running there is a danger of
         * executing instructions from stale caches if icache flush is
         * delayed.
         */
        a->memflags |= MEMF_no_icache_flush;
    }

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( i != a->nr_done && hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, a->extent_list, i, 1)) )
            goto out;

        if ( a->memflags & MEMF_populate_on_demand )
        {
            /* Disallow populating PoD pages on oneself. */
            if ( d == curr_d )
                goto out;

            if ( guest_physmap_mark_populate_on_demand(d, gpfn,
                                                       a->extent_order) < 0 )
                goto out;
        }
        else
        {
            if ( is_domain_direct_mapped(d) )
            {
                mfn = gpfn;

                for ( j = 0; j < (1U << a->extent_order); j++, mfn++ )
                {
                    if ( !mfn_valid(_mfn(mfn)) )
                    {
                        gdprintk(XENLOG_INFO, "Invalid mfn %#"PRI_xen_pfn"\n",
                                 mfn);
                        goto out;
                    }

                    page = mfn_to_page(mfn);
                    if ( !get_page(page, d) )
                    {
                        gdprintk(XENLOG_INFO,
                                 "mfn %#"PRI_xen_pfn" doesn't belong to d%d\n",
                                  mfn, d->domain_id);
                        goto out;
                    }
                    put_page(page);
                }

                mfn = gpfn;
            }
#ifdef XEN_NUMA_POLICY
            else if ( a->extent_order > dom_memalloc_max_order )
                goto out;
#endif
            else
            {
                page = alloc_domheap_pages(d, a->extent_order, a->memflags);

                if ( unlikely(!page) )
                {
                    if ( !tmem_enabled() || a->extent_order )
                        gdprintk(XENLOG_INFO,
                                 "Could not allocate order=%u extent: id=%d memflags=%#x (%u of %u)\n",
                                 a->extent_order, d->domain_id, a->memflags,
                                 i, a->nr_extents);
                    goto out;
                }

                if ( unlikely(a->memflags & MEMF_no_tlbflush) )
                {
                    for ( j = 0; j < (1U << a->extent_order); j++ )
                        accumulate_tlbflush(&need_tlbflush, &page[j],
                                            &tlbflush_timestamp);
                }

                mfn = page_to_mfn(page);
            }

            guest_physmap_add_page(d, _gfn(gpfn), _mfn(mfn), a->extent_order);

#ifdef XEN_NUMA_POLICY
            register_for_realloc(d, gpfn, a->extent_order);
#endif 

            if ( !paging_mode_translate(d) )
            {
                for ( j = 0; j < (1U << a->extent_order); j++ )
                    set_gpfn_from_mfn(mfn + j, gpfn + j);

                /* Inform the domain of the new page's machine address. */ 
                if ( unlikely(__copy_to_guest_offset(a->extent_list, i, &mfn, 1)) )
                    goto out;
            }
        }
    }

out:
    if ( need_tlbflush )
        filtered_flush_tlb_mask(tlbflush_timestamp);

    if ( a->memflags & MEMF_no_icache_flush )
        invalidate_icache();

    a->nr_done = i;
}

int guest_remove_page(struct domain *d, unsigned long gmfn)
{
    struct page_info *page;
#ifdef CONFIG_X86
    p2m_type_t p2mt;
#endif
    mfn_t mfn;
    int rc;

#ifdef CONFIG_X86
    mfn = get_gfn_query(d, gmfn, &p2mt);
    if ( unlikely(p2m_is_paging(p2mt)) )
    {
        rc = guest_physmap_remove_page(d, _gfn(gmfn), mfn, 0);
        put_gfn(d, gmfn);

        if ( rc )
            return rc;

        /* If the page hasn't yet been paged out, there is an
         * actual page that needs to be released. */
        if ( p2mt == p2m_ram_paging_out )
        {
            ASSERT(mfn_valid(mfn));
            page = mfn_to_page(mfn_x(mfn));
            if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
                put_page(page);
        }
        p2m_mem_paging_drop_page(d, gmfn, p2mt);

        return 0;
    }
    if ( p2mt == p2m_mmio_direct )
    {
        rc = clear_mmio_p2m_entry(d, gmfn, mfn, PAGE_ORDER_4K);
        put_gfn(d, gmfn);

        return rc;
    }
#else
    mfn = gfn_to_mfn(d, _gfn(gmfn));
#endif
    if ( unlikely(!mfn_valid(mfn)) )
    {
        put_gfn(d, gmfn);
        gdprintk(XENLOG_INFO, "Domain %u page number %lx invalid\n",
                d->domain_id, gmfn);

        return -EINVAL;
    }
            
#ifdef CONFIG_X86
    if ( p2m_is_shared(p2mt) )
    {
        /*
         * Unshare the page, bail out on error. We unshare because we
         * might be the only one using this shared page, and we need to
         * trigger proper cleanup. Once done, this is like any other page.
         */
        rc = mem_sharing_unshare_page(d, gmfn, 0);
        if ( rc )
        {
            put_gfn(d, gmfn);
            (void)mem_sharing_notify_enomem(d, gmfn, 0);

            return rc;
        }
        /* Maybe the mfn changed */
        mfn = get_gfn_query_unlocked(d, gmfn, &p2mt);
        ASSERT(!p2m_is_shared(p2mt));
    }
#endif /* CONFIG_X86 */

    page = mfn_to_page(mfn_x(mfn));
    if ( unlikely(!get_page(page, d)) )
    {
        put_gfn(d, gmfn);
        gdprintk(XENLOG_INFO, "Bad page free for domain %u\n", d->domain_id);

        return -ENXIO;
    }

    rc = guest_physmap_remove_page(d, _gfn(gmfn), mfn, 0);

#ifdef _PGT_pinned
    if ( !rc && test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
        put_page_and_type(page);
#endif

    /*
     * With the lack of an IOMMU on some platforms, domains with DMA-capable
     * device must retrieve the same pfn when the hypercall populate_physmap
     * is called.
     *
     * For this purpose (and to match populate_physmap() behavior), the page
     * is kept allocated.
     */
    if ( !rc && !is_domain_direct_mapped(d) &&
         test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    put_page(page);
    put_gfn(d, gmfn);

    return rc;
}

static void decrease_reservation(struct memop_args *a)
{
    unsigned long i, j;
    xen_pfn_t gmfn;

    if ( !guest_handle_subrange_okay(a->extent_list, a->nr_done,
                                     a->nr_extents-1) ||
         a->extent_order > max_order(current->domain) )
        return;

    for ( i = a->nr_done; i < a->nr_extents; i++ )
    {
        if ( i != a->nr_done && hypercall_preempt_check() )
        {
            a->preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gmfn, a->extent_list, i, 1)) )
            goto out;

        if ( tb_init_done )
        {
            struct {
                u64 gfn;
                int d:16,order:16;
            } t;

            t.gfn = gmfn;
            t.d = a->domain->domain_id;
            t.order = a->extent_order;
        
            __trace_var(TRC_MEM_DECREASE_RESERVATION, 0, sizeof(t), &t);
        }

        /* See if populate-on-demand wants to handle this */
        if ( is_hvm_domain(a->domain)
             && p2m_pod_decrease_reservation(a->domain, _gfn(gmfn),
                                             a->extent_order) )
            continue;

        for ( j = 0; j < (1 << a->extent_order); j++ )
            if ( guest_remove_page(a->domain, gmfn + j) )
                goto out;
    }

 out:
    a->nr_done = i;
}

static bool propagate_node(unsigned int xmf, unsigned int *memflags)
{
    const struct domain *currd = current->domain;

    BUILD_BUG_ON(XENMEMF_get_node(0) != NUMA_NO_NODE);
    BUILD_BUG_ON(MEMF_get_node(0) != NUMA_NO_NODE);

    if ( XENMEMF_get_node(xmf) == NUMA_NO_NODE )
        return true;

    if ( is_hardware_domain(currd) || is_control_domain(currd) )
    {
        if ( XENMEMF_get_node(xmf) >= MAX_NUMNODES )
            return false;

        *memflags |= MEMF_node(XENMEMF_get_node(xmf));
        if ( xmf & XENMEMF_exact_node_request )
            *memflags |= MEMF_exact_node;
    }
    else if ( xmf & XENMEMF_exact_node_request )
        return false;

    return true;
}

static long memory_exchange(XEN_GUEST_HANDLE_PARAM(xen_memory_exchange_t) arg)
{
    struct xen_memory_exchange exch;
    PAGE_LIST_HEAD(in_chunk_list);
    PAGE_LIST_HEAD(out_chunk_list);
    unsigned long in_chunk_order, out_chunk_order;
    xen_pfn_t     gpfn, gmfn, mfn;
    unsigned long i, j, k;
    unsigned int  memflags = 0;
    long          rc = 0;
    struct domain *d;
    struct page_info *page;

    if ( copy_from_guest(&exch, arg, 1) )
        return -EFAULT;

    if ( max(exch.in.extent_order, exch.out.extent_order) >
         max_order(current->domain) )
    {
        rc = -EPERM;
        goto fail_early;
    }

    /* Various sanity checks. */
    if ( (exch.nr_exchanged > exch.in.nr_extents) ||
         /* Input and output domain identifiers match? */
         (exch.in.domid != exch.out.domid) ||
         /* Sizes of input and output lists do not overflow a long? */
         ((~0UL >> exch.in.extent_order) < exch.in.nr_extents) ||
         ((~0UL >> exch.out.extent_order) < exch.out.nr_extents) ||
         /* Sizes of input and output lists match? */
         ((exch.in.nr_extents << exch.in.extent_order) !=
          (exch.out.nr_extents << exch.out.extent_order)) )
    {
        rc = -EINVAL;
        goto fail_early;
    }

    if ( !guest_handle_subrange_okay(exch.in.extent_start, exch.nr_exchanged,
                                     exch.in.nr_extents - 1) )
    {
        rc = -EFAULT;
        goto fail_early;
    }

    if ( exch.in.extent_order <= exch.out.extent_order )
    {
        in_chunk_order  = exch.out.extent_order - exch.in.extent_order;
        out_chunk_order = 0;

        if ( !guest_handle_subrange_okay(exch.out.extent_start,
                                         exch.nr_exchanged >> in_chunk_order,
                                         exch.out.nr_extents - 1) )
        {
            rc = -EFAULT;
            goto fail_early;
        }
    }
    else
    {
        in_chunk_order  = 0;
        out_chunk_order = exch.in.extent_order - exch.out.extent_order;

        if ( !guest_handle_subrange_okay(exch.out.extent_start,
                                         exch.nr_exchanged << out_chunk_order,
                                         exch.out.nr_extents - 1) )
        {
            rc = -EFAULT;
            goto fail_early;
        }
    }

    if ( unlikely(!propagate_node(exch.out.mem_flags, &memflags)) )
    {
        rc = -EINVAL;
        goto fail_early;
    }

    d = rcu_lock_domain_by_any_id(exch.in.domid);
    if ( d == NULL )
    {
        rc = -ESRCH;
        goto fail_early;
    }

    rc = xsm_memory_exchange(XSM_TARGET, d);
    if ( rc )
    {
        rcu_unlock_domain(d);
        goto fail_early;
    }

    memflags |= MEMF_bits(domain_clamp_alloc_bitsize(
        d,
        XENMEMF_get_address_bits(exch.out.mem_flags) ? :
        (BITS_PER_LONG+PAGE_SHIFT)));

    for ( i = (exch.nr_exchanged >> in_chunk_order);
          i < (exch.in.nr_extents >> in_chunk_order);
          i++ )
    {
        if ( i != (exch.nr_exchanged >> in_chunk_order) &&
             hypercall_preempt_check() )
        {
            exch.nr_exchanged = i << in_chunk_order;
            rcu_unlock_domain(d);
            if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
                return -EFAULT;
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh", XENMEM_exchange, arg);
        }

        /* Steal a chunk's worth of input pages from the domain. */
        for ( j = 0; j < (1UL << in_chunk_order); j++ )
        {
            if ( unlikely(__copy_from_guest_offset(
                &gmfn, exch.in.extent_start, (i<<in_chunk_order)+j, 1)) )
            {
                rc = -EFAULT;
                goto fail;
            }

            for ( k = 0; k < (1UL << exch.in.extent_order); k++ )
            {
#ifdef CONFIG_X86
                p2m_type_t p2mt;

                /* Shared pages cannot be exchanged */
                mfn = mfn_x(get_gfn_unshare(d, gmfn + k, &p2mt));
                if ( p2m_is_shared(p2mt) )
                {
                    put_gfn(d, gmfn + k);
                    rc = -ENOMEM;
                    goto fail; 
                }
#else /* !CONFIG_X86 */
                mfn = mfn_x(gfn_to_mfn(d, _gfn(gmfn + k)));
#endif
                if ( unlikely(!mfn_valid(_mfn(mfn))) )
                {
                    put_gfn(d, gmfn + k);
                    rc = -EINVAL;
                    goto fail;
                }

                page = mfn_to_page(mfn);

                rc = steal_page(d, page, MEMF_no_refcount);
                if ( unlikely(rc) )
                {
                    put_gfn(d, gmfn + k);
                    goto fail;
                }

                page_list_add(page, &in_chunk_list);
                put_gfn(d, gmfn + k);
            }
        }

        /* Allocate a chunk's worth of anonymous output pages. */
        for ( j = 0; j < (1UL << out_chunk_order); j++ )
        {
            page = alloc_domheap_pages(d, exch.out.extent_order,
                                       MEMF_no_owner | memflags);
            if ( unlikely(page == NULL) )
            {
                rc = -ENOMEM;
                goto fail;
            }

            page_list_add(page, &out_chunk_list);
        }

        /*
         * Success! Beyond this point we cannot fail for this chunk.
         */

        /* Destroy final reference to each input page. */
        while ( (page = page_list_remove_head(&in_chunk_list)) )
        {
            unsigned long gfn;

            if ( !test_and_clear_bit(_PGC_allocated, &page->count_info) )
                BUG();
            mfn = page_to_mfn(page);
            gfn = mfn_to_gmfn(d, mfn);
            /* Pages were unshared above */
            BUG_ON(SHARED_M2P(gfn));
            if ( guest_physmap_remove_page(d, _gfn(gfn), _mfn(mfn), 0) )
                domain_crash(d);
            put_page(page);
        }

        /* Assign each output page to the domain. */
        for ( j = 0; (page = page_list_remove_head(&out_chunk_list)); ++j )
        {
            if ( assign_pages(d, page, exch.out.extent_order,
                              MEMF_no_refcount) )
            {
                unsigned long dec_count;
                bool_t drop_dom_ref;

                /*
                 * Pages in in_chunk_list is stolen without
                 * decreasing the tot_pages. If the domain is dying when
                 * assign pages, we need decrease the count. For those pages
                 * that has been assigned, it should be covered by
                 * domain_relinquish_resources().
                 */
                dec_count = (((1UL << exch.in.extent_order) *
                              (1UL << in_chunk_order)) -
                             (j * (1UL << exch.out.extent_order)));

                spin_lock(&d->page_alloc_lock);
                drop_dom_ref = (dec_count &&
                                !domain_adjust_tot_pages(d, -dec_count));
                spin_unlock(&d->page_alloc_lock);

                if ( drop_dom_ref )
                    put_domain(d);

                free_domheap_pages(page, exch.out.extent_order);
                goto dying;
            }

            if ( __copy_from_guest_offset(&gpfn, exch.out.extent_start,
                                          (i << out_chunk_order) + j, 1) )
            {
                rc = -EFAULT;
                continue;
            }

            mfn = page_to_mfn(page);
            guest_physmap_add_page(d, _gfn(gpfn), _mfn(mfn),
                                   exch.out.extent_order);

            if ( !paging_mode_translate(d) )
            {
                for ( k = 0; k < (1UL << exch.out.extent_order); k++ )
                    set_gpfn_from_mfn(mfn + k, gpfn + k);
                if ( __copy_to_guest_offset(exch.out.extent_start,
                                            (i << out_chunk_order) + j,
                                            &mfn, 1) )
                    rc = -EFAULT;
            }
        }
        BUG_ON( !(d->is_dying) && (j != (1UL << out_chunk_order)) );

        if ( rc )
            goto fail;
    }

    exch.nr_exchanged = exch.in.nr_extents;
    if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    rcu_unlock_domain(d);
    return rc;

    /*
     * Failed a chunk! Free any partial chunk work. Tell caller how many
     * chunks succeeded.
     */
 fail:
    /* Reassign any input pages we managed to steal. */
    while ( (page = page_list_remove_head(&in_chunk_list)) )
        if ( assign_pages(d, page, 0, MEMF_no_refcount) )
        {
            BUG_ON(!d->is_dying);
            if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
                put_page(page);
        }

 dying:
    rcu_unlock_domain(d);
    /* Free any output pages we managed to allocate. */
    while ( (page = page_list_remove_head(&out_chunk_list)) )
        free_domheap_pages(page, exch.out.extent_order);

    exch.nr_exchanged = i << in_chunk_order;

 fail_early:
    if ( __copy_field_to_guest(arg, &exch, nr_exchanged) )
        rc = -EFAULT;
    return rc;
}

static int xenmem_add_to_physmap(struct domain *d,
                                 struct xen_add_to_physmap *xatp,
                                 unsigned int start)
{
    unsigned int done = 0;
    long rc = 0;
    union xen_add_to_physmap_batch_extra extra;

    if ( xatp->space != XENMAPSPACE_gmfn_foreign )
        extra.res0 = 0;
    else
        extra.foreign_domid = DOMID_INVALID;

    if ( xatp->space != XENMAPSPACE_gmfn_range )
        return xenmem_add_to_physmap_one(d, xatp->space, extra,
                                         xatp->idx, _gfn(xatp->gpfn));

    if ( xatp->size < start )
        return -EILSEQ;

    xatp->idx += start;
    xatp->gpfn += start;
    xatp->size -= start;

#ifdef CONFIG_HAS_PASSTHROUGH
    if ( need_iommu(d) )
        this_cpu(iommu_dont_flush_iotlb) = 1;
#endif

    while ( xatp->size > done )
    {
        rc = xenmem_add_to_physmap_one(d, xatp->space, extra,
                                       xatp->idx, _gfn(xatp->gpfn));
        if ( rc < 0 )
            break;

        xatp->idx++;
        xatp->gpfn++;

        /* Check for continuation if it's not the last iteration. */
        if ( xatp->size > ++done && hypercall_preempt_check() )
        {
            rc = start + done;
            break;
        }
    }

#ifdef CONFIG_HAS_PASSTHROUGH
    if ( need_iommu(d) )
    {
        int ret;

        this_cpu(iommu_dont_flush_iotlb) = 0;

        ret = iommu_iotlb_flush(d, xatp->idx - done, done);
        if ( unlikely(ret) && rc >= 0 )
            rc = ret;

        ret = iommu_iotlb_flush(d, xatp->gpfn - done, done);
        if ( unlikely(ret) && rc >= 0 )
            rc = ret;
    }
#endif

    return rc;
}

static int xenmem_add_to_physmap_batch(struct domain *d,
                                       struct xen_add_to_physmap_batch *xatpb,
                                       unsigned int start)
{
    unsigned int done = 0;
    int rc;

    if ( xatpb->size < start )
        return -EILSEQ;

    guest_handle_add_offset(xatpb->idxs, start);
    guest_handle_add_offset(xatpb->gpfns, start);
    guest_handle_add_offset(xatpb->errs, start);
    xatpb->size -= start;

    while ( xatpb->size > done )
    {
        xen_ulong_t idx;
        xen_pfn_t gpfn;

        if ( unlikely(__copy_from_guest_offset(&idx, xatpb->idxs, 0, 1)) )
        {
            rc = -EFAULT;
            goto out;
        }

        if ( unlikely(__copy_from_guest_offset(&gpfn, xatpb->gpfns, 0, 1)) )
        {
            rc = -EFAULT;
            goto out;
        }

        rc = xenmem_add_to_physmap_one(d, xatpb->space,
                                       xatpb->u,
                                       idx, _gfn(gpfn));

        if ( unlikely(__copy_to_guest_offset(xatpb->errs, 0, &rc, 1)) )
        {
            rc = -EFAULT;
            goto out;
        }

        guest_handle_add_offset(xatpb->idxs, 1);
        guest_handle_add_offset(xatpb->gpfns, 1);
        guest_handle_add_offset(xatpb->errs, 1);

        /* Check for continuation if it's not the last iteration. */
        if ( xatpb->size > ++done && hypercall_preempt_check() )
        {
            rc = start + done;
            goto out;
        }
    }

    rc = 0;

out:
    return rc;
}

static int construct_memop_from_reservation(
               const struct xen_memory_reservation *r,
               struct memop_args *a)
{
    unsigned int address_bits;

    a->extent_list  = r->extent_start;
    a->nr_extents   = r->nr_extents;
    a->extent_order = r->extent_order;
    a->memflags     = 0;

    address_bits = XENMEMF_get_address_bits(r->mem_flags);
    if ( (address_bits != 0) &&
         (address_bits < (get_order_from_pages(max_page) + PAGE_SHIFT)) )
    {
        if ( address_bits <= PAGE_SHIFT )
            return -EINVAL;
        a->memflags = MEMF_bits(address_bits);
    }

    if ( r->mem_flags & XENMEMF_vnode )
    {
        nodeid_t vnode, pnode;
        struct domain *d = a->domain;

        read_lock(&d->vnuma_rwlock);
        if ( d->vnuma )
        {
            vnode = XENMEMF_get_node(r->mem_flags);
            if ( vnode >= d->vnuma->nr_vnodes )
            {
                read_unlock(&d->vnuma_rwlock);
                return -EINVAL;
            }

            pnode = d->vnuma->vnode_to_pnode[vnode];
            if ( pnode != NUMA_NO_NODE )
            {
                a->memflags |= MEMF_node(pnode);
                if ( r->mem_flags & XENMEMF_exact_node_request )
                    a->memflags |= MEMF_exact_node;
            }
        }
        read_unlock(&d->vnuma_rwlock);
    }
    else if ( unlikely(!propagate_node(r->mem_flags, &a->memflags)) )
        return -EINVAL;

    return 0;
}

#ifdef CONFIG_HAS_PASSTHROUGH
struct get_reserved_device_memory {
    struct xen_reserved_device_memory_map map;
    unsigned int used_entries;
};

static int get_reserved_device_memory(xen_pfn_t start, xen_ulong_t nr,
                                      u32 id, void *ctxt)
{
    struct get_reserved_device_memory *grdm = ctxt;
    u32 sbdf = PCI_SBDF3(grdm->map.dev.pci.seg, grdm->map.dev.pci.bus,
                         grdm->map.dev.pci.devfn);

    if ( !(grdm->map.flags & XENMEM_RDM_ALL) && (sbdf != id) )
        return 0;

    if ( grdm->used_entries < grdm->map.nr_entries )
    {
        struct xen_reserved_device_memory rdm = {
            .start_pfn = start, .nr_pages = nr
        };

        if ( __copy_to_guest_offset(grdm->map.buffer, grdm->used_entries,
                                    &rdm, 1) )
            return -EFAULT;
    }

    ++grdm->used_entries;

    return 1;
}
#endif

static long xatp_permission_check(struct domain *d, unsigned int space)
{
    /*
     * XENMAPSPACE_dev_mmio mapping is only supported for hardware Domain
     * to map this kind of space to itself.
     */
    if ( (space == XENMAPSPACE_dev_mmio) &&
         (!is_hardware_domain(current->domain) || (d != current->domain)) )
        return -EACCES;

    return xsm_add_to_physmap(XSM_TARGET, current->domain, d);
}

long do_memory_op(unsigned long cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d, *curr_d = current->domain;
    long rc;
    struct xen_memory_reservation reservation;
    struct memop_args args;
    domid_t domid;
    unsigned long start_extent = cmd >> MEMOP_EXTENT_SHIFT;
    int op = cmd & MEMOP_CMD_MASK;

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( copy_from_guest(&reservation, arg, 1) )
            return start_extent;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (UINT_MAX >> MEMOP_EXTENT_SHIFT) )
            return start_extent;

        if ( unlikely(start_extent >= reservation.nr_extents) )
            return start_extent;

        d = rcu_lock_domain_by_any_id(reservation.domid);
        if ( d == NULL )
            return start_extent;
        args.domain = d;

        if ( construct_memop_from_reservation(&reservation, &args) )
        {
            rcu_unlock_domain(d);
            return start_extent;
        }

        args.nr_done   = start_extent;
        args.preempted = 0;

        if ( op == XENMEM_populate_physmap
             && (reservation.mem_flags & XENMEMF_populate_on_demand) )
            args.memflags |= MEMF_populate_on_demand;

        if ( xsm_memory_adjust_reservation(XSM_TARGET, curr_d, d) )
        {
            rcu_unlock_domain(d);
            return start_extent;
        }

        switch ( op )
        {
        case XENMEM_increase_reservation:
            increase_reservation(&args);
            break;
        case XENMEM_decrease_reservation:
            decrease_reservation(&args);
            break;
        default: /* XENMEM_populate_physmap */
            populate_physmap(&args);
            break;
        }

        rcu_unlock_domain(d);

        rc = args.nr_done;

        if ( args.preempted )
            return hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh",
                op | (rc << MEMOP_EXTENT_SHIFT), arg);

        break;

    case XENMEM_exchange:
        if ( unlikely(start_extent) )
            return -EINVAL;

        rc = memory_exchange(guest_handle_cast(arg, xen_memory_exchange_t));
        break;

    case XENMEM_maximum_ram_page:
        if ( unlikely(start_extent) )
            return -EINVAL;

        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
    case XENMEM_maximum_gpfn:
        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&domid, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_memory_stat_reservation(XSM_TARGET, curr_d, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        switch ( op )
        {
        case XENMEM_current_reservation:
            rc = d->tot_pages;
            break;
        case XENMEM_maximum_reservation:
            rc = d->max_pages;
            break;
        default:
            ASSERT(op == XENMEM_maximum_gpfn);
            rc = domain_get_maximum_gpfn(d);
            break;
        }

        rcu_unlock_domain(d);

        break;

    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;

        BUILD_BUG_ON((typeof(xatp.size))-1 > (UINT_MAX >> MEMOP_EXTENT_SHIFT));

        /* Check for malicious or buggy input. */
        if ( start_extent != (typeof(xatp.size))start_extent )
            return -EDOM;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        /* Foreign mapping is only possible via add_to_physmap_batch. */
        if ( xatp.space == XENMAPSPACE_gmfn_foreign )
            return -ENOSYS;

        d = rcu_lock_domain_by_any_id(xatp.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xatp_permission_check(d, xatp.space);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap(d, &xatp, start_extent);

        rcu_unlock_domain(d);

        if ( xatp.space == XENMAPSPACE_gmfn_range && rc > 0 )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_memory_op, "lh",
                     op | (rc << MEMOP_EXTENT_SHIFT), arg);

        return rc;
    }

    case XENMEM_add_to_physmap_batch:
    {
        struct xen_add_to_physmap_batch xatpb;

        BUILD_BUG_ON((typeof(xatpb.size))-1 >
                     (UINT_MAX >> MEMOP_EXTENT_SHIFT));

        /* Check for malicious or buggy input. */
        if ( start_extent != (typeof(xatpb.size))start_extent )
            return -EDOM;

        if ( copy_from_guest(&xatpb, arg, 1) ||
             !guest_handle_okay(xatpb.idxs, xatpb.size) ||
             !guest_handle_okay(xatpb.gpfns, xatpb.size) ||
             !guest_handle_okay(xatpb.errs, xatpb.size) )
            return -EFAULT;

        /* This mapspace is unsupported for this hypercall. */
        if ( xatpb.space == XENMAPSPACE_gmfn_range )
            return -EOPNOTSUPP;

        d = rcu_lock_domain_by_any_id(xatpb.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xatp_permission_check(d, xatpb.space);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = xenmem_add_to_physmap_batch(d, &xatpb, start_extent);

        rcu_unlock_domain(d);

        if ( rc > 0 )
            rc = hypercall_create_continuation(
                    __HYPERVISOR_memory_op, "lh",
                    op | (rc << MEMOP_EXTENT_SHIFT), arg);

        return rc;
    }

    case XENMEM_remove_from_physmap:
    {
        struct xen_remove_from_physmap xrfp;
        struct page_info *page;

        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&xrfp, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(xrfp.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_remove_from_physmap(XSM_TARGET, curr_d, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        page = get_page_from_gfn(d, xrfp.gpfn, NULL, P2M_ALLOC);
        if ( page )
        {
            rc = guest_physmap_remove_page(d, _gfn(xrfp.gpfn),
                                           _mfn(page_to_mfn(page)), 0);
            put_page(page);
        }
        else
            rc = -ENOENT;

        rcu_unlock_domain(d);

        break;
    }

    case XENMEM_access_op:
        rc = mem_access_memop(cmd, guest_handle_cast(arg, xen_mem_access_op_t));
        break;

    case XENMEM_claim_pages:
        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&reservation, arg, 1) )
            return -EFAULT;

        if ( !guest_handle_is_null(reservation.extent_start) )
            return -EINVAL;

        if ( reservation.extent_order != 0 )
            return -EINVAL;

        if ( reservation.mem_flags != 0 )
            return -EINVAL;

        d = rcu_lock_domain_by_id(reservation.domid);
        if ( d == NULL )
            return -EINVAL;

        rc = xsm_claim_pages(XSM_PRIV, d);

        if ( !rc )
            rc = domain_set_outstanding_pages(d, reservation.nr_extents);

        rcu_unlock_domain(d);

        break;

    case XENMEM_get_vnumainfo:
    {
        struct xen_vnuma_topology_info topology;
        unsigned int dom_vnodes, dom_vranges, dom_vcpus;
        struct vnuma_info tmp;

        if ( unlikely(start_extent) )
            return -EINVAL;

        /*
         * Guest passes nr_vnodes, number of regions and nr_vcpus thus
         * we know how much memory guest has allocated.
         */
        if ( copy_from_guest(&topology, arg, 1 ))
            return -EFAULT;

        if ( topology.pad != 0 )
            return -EINVAL;

        if ( (d = rcu_lock_domain_by_any_id(topology.domid)) == NULL )
            return -ESRCH;

        rc = xsm_get_vnumainfo(XSM_TARGET, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        read_lock(&d->vnuma_rwlock);

        if ( d->vnuma == NULL )
        {
            read_unlock(&d->vnuma_rwlock);
            rcu_unlock_domain(d);
            return -EOPNOTSUPP;
        }

        dom_vnodes = d->vnuma->nr_vnodes;
        dom_vranges = d->vnuma->nr_vmemranges;
        dom_vcpus = d->max_vcpus;

        /*
         * Copied from guest values may differ from domain vnuma config.
         * Check here guest parameters make sure we dont overflow.
         * Additionaly check padding.
         */
        if ( topology.nr_vnodes < dom_vnodes      ||
             topology.nr_vcpus < dom_vcpus        ||
             topology.nr_vmemranges < dom_vranges )
        {
            read_unlock(&d->vnuma_rwlock);
            rcu_unlock_domain(d);

            topology.nr_vnodes = dom_vnodes;
            topology.nr_vcpus = dom_vcpus;
            topology.nr_vmemranges = dom_vranges;

            /* Copy back needed values. */
            return __copy_to_guest(arg, &topology, 1) ? -EFAULT : -ENOBUFS;
        }

        read_unlock(&d->vnuma_rwlock);

        tmp.vdistance = xmalloc_array(unsigned int, dom_vnodes * dom_vnodes);
        tmp.vmemrange = xmalloc_array(xen_vmemrange_t, dom_vranges);
        tmp.vcpu_to_vnode = xmalloc_array(unsigned int, dom_vcpus);

        if ( tmp.vdistance == NULL ||
             tmp.vmemrange == NULL ||
             tmp.vcpu_to_vnode == NULL )
        {
            rc = -ENOMEM;
            goto vnumainfo_out;
        }

        /*
         * Check if vnuma info has changed and if the allocated arrays
         * are not big enough.
         */
        read_lock(&d->vnuma_rwlock);

        if ( dom_vnodes < d->vnuma->nr_vnodes ||
             dom_vranges < d->vnuma->nr_vmemranges ||
             dom_vcpus < d->max_vcpus )
        {
            read_unlock(&d->vnuma_rwlock);
            rc = -EAGAIN;
            goto vnumainfo_out;
        }

        dom_vnodes = d->vnuma->nr_vnodes;
        dom_vranges = d->vnuma->nr_vmemranges;
        dom_vcpus = d->max_vcpus;

        memcpy(tmp.vmemrange, d->vnuma->vmemrange,
               sizeof(*d->vnuma->vmemrange) * dom_vranges);
        memcpy(tmp.vdistance, d->vnuma->vdistance,
               sizeof(*d->vnuma->vdistance) * dom_vnodes * dom_vnodes);
        memcpy(tmp.vcpu_to_vnode, d->vnuma->vcpu_to_vnode,
               sizeof(*d->vnuma->vcpu_to_vnode) * dom_vcpus);

        read_unlock(&d->vnuma_rwlock);

        rc = -EFAULT;

        if ( copy_to_guest(topology.vmemrange.h, tmp.vmemrange,
                           dom_vranges) != 0 )
            goto vnumainfo_out;

        if ( copy_to_guest(topology.vdistance.h, tmp.vdistance,
                           dom_vnodes * dom_vnodes) != 0 )
            goto vnumainfo_out;

        if ( copy_to_guest(topology.vcpu_to_vnode.h, tmp.vcpu_to_vnode,
                           dom_vcpus) != 0 )
            goto vnumainfo_out;

        topology.nr_vnodes = dom_vnodes;
        topology.nr_vcpus = dom_vcpus;
        topology.nr_vmemranges = dom_vranges;

        rc = __copy_to_guest(arg, &topology, 1) ? -EFAULT : 0;

 vnumainfo_out:
        rcu_unlock_domain(d);

        xfree(tmp.vdistance);
        xfree(tmp.vmemrange);
        xfree(tmp.vcpu_to_vnode);
        break;
    }

#ifdef CONFIG_HAS_PASSTHROUGH
    case XENMEM_reserved_device_memory_map:
    {
        struct get_reserved_device_memory grdm;

        if ( unlikely(start_extent) )
            return -EINVAL;

        if ( copy_from_guest(&grdm.map, arg, 1) ||
             !guest_handle_okay(grdm.map.buffer, grdm.map.nr_entries) )
            return -EFAULT;

        if ( grdm.map.flags & ~XENMEM_RDM_ALL )
            return -EINVAL;

        grdm.used_entries = 0;
        rc = iommu_get_reserved_device_memory(get_reserved_device_memory,
                                              &grdm);

        if ( !rc && grdm.map.nr_entries < grdm.used_entries )
            rc = -ENOBUFS;
        grdm.map.nr_entries = grdm.used_entries;
        if ( __copy_to_guest(arg, &grdm.map, 1) )
            rc = -EFAULT;

        break;
    }
#endif

    default:
        rc = arch_memory_op(cmd, arg);
        break;
    }

    return rc;
}

void clear_domain_page(mfn_t mfn)
{
    void *ptr = map_domain_page(mfn);

    clear_page(ptr);
    unmap_domain_page(ptr);
}

void copy_domain_page(mfn_t dest, mfn_t source)
{
    const void *src = map_domain_page(source);
    void *dst = map_domain_page(dest);

    copy_page(dst, src);
    unmap_domain_page(dst);
    unmap_domain_page(src);
}

void destroy_ring_for_helper(
    void **_va, struct page_info *page)
{
    void *va = *_va;

    if ( va != NULL )
    {
        unmap_domain_page_global(va);
        put_page_and_type(page);
        *_va = NULL;
    }
}

int prepare_ring_for_helper(
    struct domain *d, unsigned long gmfn, struct page_info **_page,
    void **_va)
{
    struct page_info *page;
    p2m_type_t p2mt;
    void *va;

    page = get_page_from_gfn(d, gmfn, &p2mt, P2M_UNSHARE);

#ifdef CONFIG_HAS_MEM_PAGING
    if ( p2m_is_paging(p2mt) )
    {
        if ( page )
            put_page(page);
        p2m_mem_paging_populate(d, gmfn);
        return -ENOENT;
    }
#endif
#ifdef CONFIG_HAS_MEM_SHARING
    if ( p2m_is_shared(p2mt) )
    {
        if ( page )
            put_page(page);
        return -ENOENT;
    }
#endif

    if ( !page )
        return -EINVAL;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        return -EINVAL;
    }

    va = __map_domain_page_global(page);
    if ( va == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    *_va = va;
    *_page = page;

    return 0;
}

#ifdef XEN_NUMA_POLICY

#define __atomic64_read(src)   read_u64_atomic(src)

static inline void __atomic64_add(unsigned long *dest, unsigned long add)
{
    asm volatile ("lock; addq %1, %0"
                  : "=m" (*(volatile unsigned long *) dest)
                  : "r" (add), "m" (*(volatile unsigned long *) dest));
}

static inline void __atomic64_sub(unsigned long *dest, unsigned long sub)
{
    asm volatile ("lock; subq %1, %0"
                  : "=m" (*(volatile unsigned long *) dest)
                  : "r" (sub), "m" (*(volatile unsigned long *) dest));
}

struct realloc_facility *alloc_realloc_facility(void)
{
    struct realloc_facility *ptr = xzalloc(struct realloc_facility);
    int cpu, node;

    if (ptr == NULL)
        return NULL;

    rwlock_init(&ptr->token_tree_lock);

    for_each_online_cpu (cpu) {
        INIT_LIST_HEAD(&ptr->remap_bucket[cpu]);
        spin_lock_init(&ptr->remap_bucket_lock[cpu]);
        ptr->remap_last_try[cpu] = 0;
    }

    ptr->enabled = 0;
    ptr->preparing = 0;

    for (node = 0; node < MAX_NUMNODES; node++)
        ptr->page_pool_size[node] = 0;

    ptr->apply_query = 0;
    ptr->apply_done = 0;
    ptr->apply_running = 0;

    return ptr;
}

static void __free_realloc_facility(int level, void *stage)
{
    unsigned long index;
    void *ptr;
    
    if (level < REALLOC_TREE_LEVELS) {
        for (index = 0; index < ENTRY_MASK; index++) {
            ptr = ((void **) stage)[index];
            if (ptr == NULL)
                continue;
            __free_realloc_facility(level + 1, ptr);
        }
    }

    xfree(stage);
}

void free_realloc_facility(struct realloc_facility *ptr)
{
    unsigned long i;
    int node;

    if (ptr->token_tree != NULL)
        __free_realloc_facility(0, ptr->token_tree);

    for (node = 0; node < MAX_NUMNODES; node++)
        for (i=0; i<ptr->page_pool_size[node]; i++)
            free_domheap_pages(ptr->page_pool[node][i], 0);

    xfree(ptr);
}

int enable_realloc_facility(struct domain *d, int enable)
{
    if (enable) {
        d->realloc->enabled = 1;
                
        return 0;
    } else {
        /* Signal we are stopping, so other cores must stop unmapping */
        d->realloc->enabled = 0;

        /*
         * If cores were already unmapping, wait for them to finish.
         * NB: performance is not required here.
         */
        while (__atomic64_read(&d->realloc->preparing))
            ;

        /*
         * Remapping pages can be a long operation, so remap_all_pages() return
         * 1 if we need to return because of preemption, 0 if complete.
         */
        return remap_all_pages(d);
    }
}

struct realloc_token *find_realloc_token(struct realloc_facility *f,
                                         unsigned long gfn)
{
    struct realloc_token *data = NULL;
    void *stage = f->token_tree;
    unsigned long index;
    int level;

    for (level = 0; level < REALLOC_TREE_LEVELS; level++) {
        if (stage == NULL)
            break;
            
        index = ENTRY_LEVEL_INDEX(level, gfn);
        stage = ((void **) stage)[index];
    }

    data = (struct realloc_token *) stage;

    return data;
}

int insert_realloc_token(struct realloc_facility *f, struct realloc_token *t,
                         struct realloc_token *h)
{
    void **stage = &f->token_tree;
    unsigned long index, gfn = t->gfn;
    int level;
    
    for (level = 0; level < REALLOC_TREE_LEVELS; level++) {
        if (*stage == NULL)
            *stage = xzalloc_array(void *, REALLOC_TREE_ARRLEN);
        if (*stage == NULL) {
            return -1;
        }
            
        index = ENTRY_LEVEL_INDEX(level, gfn);
        stage = &((*((void ***) stage))[index]);
    }
    
    *((struct realloc_token **) stage) = t;
    return 0;
}

int remove_realloc_token(struct realloc_facility *f, struct realloc_token *t)
{
    void **stage = &f->token_tree;
    unsigned long index, gfn = t->gfn;
    int level;

    for (level = 0; level < REALLOC_TREE_LEVELS; level++) {
        if (*stage == NULL)
            return -1;
        
        index = ENTRY_LEVEL_INDEX(level, gfn);
        stage = &((*((void ***) stage))[index]);
    }

    *((struct realloc_token **) stage) = NULL;
    return 0;
}

static int __register_one_for_realloc(struct domain *d, unsigned long gfn)
{
    struct realloc_token *token, *hint;
    int ret = 0;

    write_lock(&d->realloc->token_tree_lock);

    hint = find_realloc_token(d->realloc, gfn);
    if (hint != NULL && hint->gfn == gfn)
        goto err_unlock;

    token = xmalloc(struct realloc_token);
    if (token == NULL)
        goto err_unlock;

    token->gfn = gfn;
    token->state = REALLOC_STATE_MAP;
    token->copy = 0;
    token->unmap_ticket = 0;
    token->remap_ticket = 0;

    if (insert_realloc_token(d->realloc, token, hint) != 0) {
        xfree(token);
        goto err_unlock;
    }

    ret = 1;
err_unlock:
    write_unlock(&d->realloc->token_tree_lock);
    return ret;
}

unsigned long register_for_realloc(struct domain *d, unsigned long gfn,
                                   unsigned int order)
{
    unsigned long count = 0;
    unsigned long cur, last = gfn + (1ul << order);

    for (cur = gfn; cur < last; cur++)
        if (__register_one_for_realloc(d, cur))
            count++;

    return count;
}

static int __update_ticket(unsigned long *ticket, unsigned long new)
{
    unsigned long old, expected = 0;
    
    while (new > expected) {
        old = cmpxchg(ticket, expected, new);
        if (old == expected)
            return 1;
        expected = old;
    }

    return 0;
}

static void __unmap_prepare_one(struct domain *d, unsigned long gfn,
                                unsigned long ticket)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *old;
    p2m_access_t access;
    unsigned long mfn;
    p2m_type_t type;
    struct realloc_token *token;
    int state, nstate, flags, ret = 0;

    read_lock(&d->realloc->token_tree_lock);
    token = find_realloc_token(d->realloc, gfn);
    read_unlock(&d->realloc->token_tree_lock);
    
    if (token == NULL || token->gfn != gfn)
        return;

    if (!__update_ticket(&token->unmap_ticket, ticket))
        return;
    if (ticket < token->remap_ticket)
        return;
    
    nstate = REALLOC_STATE_MAP;
    state = cmpxchg(&token->state, REALLOC_STATE_MAP, REALLOC_STATE_UBUSY);
    if (state != REALLOC_STATE_MAP)
        return;

    flags = P2M_ALLOC | P2M_UNSHARE;
    mfn = mfn_x(get_gfn_type_access(p2m, gfn, &type, &access, flags, 0));

    if ( unlikely(!mfn_valid(_mfn(mfn))) )
        goto err_gfn;

    if ( p2m_is_shared(type) )
        goto err_gfn;

    old = mfn_to_page(mfn);
    if ( unlikely(steal_page(d, old, MEMF_no_refcount)) )
        goto err_gfn;

    token->mfn = mfn;
    token->type = type;
    token->access = access;

    p2m->set_entry(p2m, _gfn(gfn), INVALID_MFN, 0, p2m_ram_paged, p2m_access_n, -1);

    ret = 1;
    nstate = REALLOC_STATE_UNMAP;
err_gfn:
    put_gfn(d, gfn);

    state = cmpxchg(&token->state, REALLOC_STATE_UBUSY, nstate);
    if (state != REALLOC_STATE_UBUSY)
        BUG();
}

unsigned long unmap_realloc(struct domain *d, unsigned long gfn,
                            unsigned long ticket)
{
    unsigned long count = 0;

    if (!d->realloc->enabled)
        return 0;

    /* Signal someone is preparing so do not die now. */
    __atomic64_add(&d->realloc->preparing, 1);

    /*
     * enabled may have been unset between the first check and our
     * notification, so recheck here.
     */
    if (!d->realloc->enabled)
        goto out;

    __unmap_prepare_one(d, gfn, ticket);
    count = 1;

out:
    __atomic64_sub(&d->realloc->preparing, 1);
    return count;
}

static int __remap_realloc_one(struct domain *d, unsigned long gfn, int copy,
                               int fault, unsigned int node,
                               unsigned long ticket)
{
    struct realloc_token *token;
    unsigned int cpu = smp_processor_id();
    int state, ret = 0;

    read_lock(&d->realloc->token_tree_lock);
    token = find_realloc_token(d->realloc, gfn);
    read_unlock(&d->realloc->token_tree_lock);

    if (token == NULL || token->gfn != gfn)
        goto err;

    if (ticket && !__update_ticket(&token->remap_ticket, ticket))
        goto out;

    /*
     * For now, UBUSY, BUSY and DELAY are transitory states so we want to
     * wait the token reach a stable state to decide what to do.
     */

    do {
        state = cmpxchg(&token->state, REALLOC_STATE_UNMAP,REALLOC_STATE_BUSY);
    } while (state == REALLOC_STATE_UBUSY ||
             state == REALLOC_STATE_BUSY);

    if (state != REALLOC_STATE_UNMAP) {

        /* If already mapped, then it's ok, do nothing */
        if (state == REALLOC_STATE_MAP || state == REALLOC_STATE_DELAY)
            goto out;
                
        goto err;
    }

    token->node = node;

    spin_lock(&d->realloc->remap_bucket_lock[cpu]);

    list_add(&token->bucket_cell, &d->realloc->remap_bucket[cpu]);

    state = cmpxchg(&token->state, REALLOC_STATE_BUSY, REALLOC_STATE_DELAY);
    if (state != REALLOC_STATE_BUSY)
        BUG();

    spin_unlock(&d->realloc->remap_bucket_lock[cpu]);

    __atomic64_add(&d->realloc->apply_query, 1);
out:
    ret = 1;
err:
    return ret;
}

unsigned long remap_realloc(struct domain *d, unsigned long gfn,
                            unsigned int node, unsigned long ticket)
{
    unsigned long count = 0;
    unsigned long query, done;

    if (__remap_realloc_one(d, gfn, 0, 0, node, ticket))
        count = 1;

    query = __atomic64_read(&d->realloc->apply_query);
    done = __atomic64_read(&d->realloc->apply_done);
    if (done + REALLOC_APPLY_TRIGGER < query)
        apply_realloc(d);
    
    return count;
}

static int __replace_page(struct domain *d, unsigned long gfn,
                          struct page_info *old, struct page_info *new,
                          p2m_type_t type, p2m_access_t access, int copy)
{
    unsigned long old_mfn = page_to_mfn(old), new_mfn = page_to_mfn(new);
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( assign_pages(d, new, 0, MEMF_no_refcount) )
        return -1;

    if (copy)
        copy_domain_page(_mfn(new_mfn), _mfn(old_mfn));

    guest_physmap_add_page(d, _gfn(gfn), _mfn(new_mfn), 0);
    
    if (type != p2m_ram_rw || access != p2m->default_access)
        p2m->set_entry(p2m, _gfn(gfn), _mfn(new_mfn), 0, type, access, -1);

    put_page(old);

    if ( !paging_mode_translate(d) )
        set_gpfn_from_mfn(new_mfn, gfn);

    return 0;
}

static struct page_info *__alloc_cached_page(struct domain *d, int node)
{
    unsigned int memflags, i;
    unsigned long mfn, *size;
    struct page_info *pg;

    memflags = domain_clamp_alloc_bitsize(d, BITS_PER_LONG + PAGE_SHIFT);
    memflags = MEMF_bits(memflags);
    memflags = memflags | MEMF_node(node);

    size = &d->realloc->page_pool_size[node];

    if (*size == 0) {
        pg = alloc_domheap_pages(NULL, REALLOC_POOL_ORDER, memflags);
        mfn = page_to_mfn(pg);
        for (i = 0; i < REALLOC_POOL_SIZE; i++)
            d->realloc->page_pool[node][i] = mfn_to_page(mfn + i);
        *size = REALLOC_POOL_SIZE;
    }
    
    (*size)--;
    return d->realloc->page_pool[node][*size];
}

static unsigned int __apply_realloc_one(struct domain *d,
                                        struct realloc_token *token)
{
    struct page_info *old = NULL;
    struct page_info *new = NULL;
    int ret, state;

    state = cmpxchg(&token->state, REALLOC_STATE_DELAY, REALLOC_STATE_BUSY);
    if (state != REALLOC_STATE_DELAY)
        return 1;

    old = mfn_to_page(token->mfn);

    new = __alloc_cached_page(d, token->node);
    if ( unlikely(new == NULL) )
        goto fail_old;
    
    raw_p2m_lock(p2m_get_hostp2m(d));
    ret = __replace_page(d, token->gfn, old, new, token->type, 
                            token->access, token->copy);
    raw_p2m_unlock(p2m_get_hostp2m(d));
    
    if ( ret )
        goto fail_new;

    goto out;
 fail_new:
    free_domheap_pages(new, 0);
 fail_old:
    /* Now reassign the old mfn to the domain */
    if ( assign_pages(d, old, 0, MEMF_no_refcount) )
        BUG();
    
 out:
    state = cmpxchg(&token->state, REALLOC_STATE_BUSY, REALLOC_STATE_MAP);
    if (state != REALLOC_STATE_BUSY)
        BUG();
    
    return 1;
}

static inline void __spin_ns(unsigned long ns)
{
    unsigned long end = NOW() + ns;
    while (NOW() < end)
        ;
}

unsigned long apply_realloc(struct domain *d)
{
    struct realloc_token *token;
    struct list_head *cell;
    unsigned long done, cpudone, count = 0;
    unsigned long query, running = -1;
    unsigned long waited;
    int cpu;

    query = __atomic64_read(&d->realloc->apply_query);
    done = __atomic64_read(&d->realloc->apply_done);
    if (done >= query)
        goto out;

    waited = 0;
    running = cmpxchg(&d->realloc->apply_running, 0, 1);
    while (running != 0) {
        __spin_ns(REALLOC_BATCH_SPIN_NS);
        waited++;
        
        done = __atomic64_read(&d->realloc->apply_done);
        if (done >= query) {
            goto out;
        }
        
        running = cmpxchg(&d->realloc->apply_running, 0, 1);
    }

    for_each_online_cpu (cpu) {
        cpudone = 0;
        spin_lock(&d->realloc->remap_bucket_lock[cpu]);

        while (!list_empty(&d->realloc->remap_bucket[cpu])) {
            cell = d->realloc->remap_bucket[cpu].next;
            token = container_of(cell, struct realloc_token, bucket_cell);
    
            __apply_realloc_one(d, token);

            list_del(cell);
            cpudone++;
        }

        spin_unlock(&d->realloc->remap_bucket_lock[cpu]);

        __atomic64_add(&d->realloc->apply_done, cpudone);
        count += cpudone;
    }

 out:
    if (running == 0)
        cmpxchg(&d->realloc->apply_running, 1, 0);
    return count;
}

unsigned long remap_realloc_now(struct domain *d, unsigned long gfn, int fault)
{
    unsigned long count = 0;
    unsigned int cpu = smp_processor_id();

    if (__remap_realloc_one(d, gfn, 0, fault, cpu_to_node(cpu), 0))
        count = 1;

    apply_realloc(d);
    return count;
}

static int __remap_all_pages(struct domain *d, int level, void *stage)
{
    unsigned long index, query, done;
    struct realloc_token *token;
    void *ptr;

    if (level < REALLOC_TREE_LEVELS) {
        for (index = 0; index <= ENTRY_MASK; index++) {
            ptr = ((void **) stage)[index];
            if (ptr == NULL)
                continue;
            if (__remap_all_pages(d, level + 1, ptr))
                return 1;
        }

        return 0;
    }

    token = (struct realloc_token *) stage;
    if (token->state == REALLOC_STATE_UNMAP)
        __remap_realloc_one(d, token->gfn, 1, 0, 0, 0);
    else
        return 0;

    query = __atomic64_read(&d->realloc->apply_query);
    done = __atomic64_read(&d->realloc->apply_done);
    if (done + REALLOC_RMALL_TRIGGER < query) {
        apply_realloc(d);
        
        if (hypercall_preempt_check())
            return 1;
    }

    return 0;
}

int remap_all_pages(struct domain *d)
{
    int rc = 0;
    
    read_lock(&d->realloc->token_tree_lock);

    if (d->realloc->token_tree != NULL)
        rc = __remap_all_pages(d, 0, d->realloc->token_tree);

    read_unlock(&d->realloc->token_tree_lock);

    if (rc)
        return 1;
    
    apply_realloc(d);
    return 0;
}

#endif /* XEN_NUMA_POLICY */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
