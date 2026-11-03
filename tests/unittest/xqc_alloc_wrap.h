#ifndef XQC_ALLOC_WRAP_H
#define XQC_ALLOC_WRAP_H

/*
 * On Linux, run_tests is linked with --wrap for malloc, calloc, realloc and
 * free, and XQC_TEST_ALLOC_WRAP is defined (tests/CMakeLists.txt). Setting
 * xqc_test_alloc_count to 0 starts counting allocations: the one numbered
 * xqc_test_alloc_fail_at returns NULL and sets xqc_test_alloc_failed.
 * Setting xqc_test_alloc_count back to -1 stops counting.
 *
 * While xqc_test_alloc_tracking is set, xqc_test_alloc_live goes up by one
 * for each allocation and down by one for each free, so that a test can
 * check what it leaves allocated.
 */
#ifdef XQC_TEST_ALLOC_WRAP

extern long xqc_test_alloc_count;
extern long xqc_test_alloc_fail_at;
extern int  xqc_test_alloc_failed;
extern int  xqc_test_alloc_tracking;
extern long xqc_test_alloc_live;

#endif

#endif
