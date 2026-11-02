#ifndef XQC_ALLOC_WRAP_H
#define XQC_ALLOC_WRAP_H

/*
 * On Linux, run_tests is linked with --wrap for malloc, calloc and realloc,
 * and XQC_TEST_ALLOC_WRAP is defined (tests/CMakeLists.txt). Setting
 * xqc_test_alloc_count to 0 starts counting allocations: the one numbered
 * xqc_test_alloc_fail_at returns NULL and sets xqc_test_alloc_failed.
 * Setting xqc_test_alloc_count back to -1 stops counting.
 */
#ifdef XQC_TEST_ALLOC_WRAP

extern long xqc_test_alloc_count;
extern long xqc_test_alloc_fail_at;
extern int  xqc_test_alloc_failed;

#endif

#endif
