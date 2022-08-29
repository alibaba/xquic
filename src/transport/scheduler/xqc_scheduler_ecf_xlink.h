
#ifndef _XQC_SCHEDULER_ECF_XLINK_H_INCLUDED_
#define _XQC_SCHEDULER_ECF_XLINK_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

typedef struct {
    int waiting;
    unsigned int r_beta;         /* marked by wh:r_beta == 1 / β */
}xqc_ecf_scheduler_t;

extern const xqc_scheduler_callback_t xqc_ecf_scheduler_cb;



#endif /* _XQC_SCHEDULER_ECF_XLINK_H_INCLUDED_ */