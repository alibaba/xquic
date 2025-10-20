#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "moq/demo/xqc_moq_demo_comm.h"
#include "moq/moq_media/dejitter/video/xqc_moq_jitter_buffer.h"

int xqc_log_fd;


#define XQC_MAX_LOG_LEN 2048
void
xqc_app_write_log(xqc_log_level_t lvl, 
    const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    if (xqc_log_fd <= 0) {
        printf("xqc_app_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_app_write_log err\n");
        return;
    }

    int write_len = write(xqc_log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("xqc_app_write_log write failed, errno: %d\n", get_sys_errno());
    }
}


int
main()
{
    xqc_log_callbacks_t log_callbacks = {
        .xqc_log_write_err = xqc_app_write_log,
        .xqc_log_write_stat = xqc_app_write_log
    };
    xqc_log_fd = open("./jitterbuf_test.log", (O_WRONLY | O_CREAT), 0644);
    xqc_log_t *log = xqc_log_init(XQC_LOG_DEBUG, 0, 1, 1, 1, NULL,
                                  &log_callbacks, NULL);

    int pid_list[10] = {0, 1, 3, 2, 5, 6, 7, 8, 9, 10};
    int group_id_list[10] = {0, 0, 0, 0, 0, 1, 1, 1, 1, 1};
    
    int length = sizeof(pid_list) / sizeof(pid_list[0]);
    xqc_moq_jitter_buffer_t *vjb_inst = xqc_moq_jitter_buffer_create(log);
    xqc_moq_video_frame_ext_t *cur_frame;
    xqc_moq_video_frame_ext_t *out_frame;
    for (int i = 0; i < length; ++i) {
        printf("on video frame. \n");
        out_frame = NULL;
        cur_frame = calloc(1, sizeof(xqc_moq_audio_frame_ext_t));
        if (i == 0 || i == 5) {
            cur_frame->video_frame.type = 0;
        } else {
            cur_frame->video_frame.type = 1;
        }
        cur_frame->video_frame.seq_num = pid_list[i];
        cur_frame->group_id = group_id_list[i];
        int ret = xqc_moq_jitter_buffer_on_video(vjb_inst, cur_frame);
        if (ret < 0) {
            printf("insert frame fail!\n");
            continue;
        }
        while (1) {
            out_frame = xqc_moq_jitter_buffer_get_video_frame(vjb_inst);
            if (out_frame == NULL) {
                printf("out_frame is NULL! \n");
                break;
            }
            printf("frame seq = %"PRIu64" \n", out_frame->video_frame.seq_num);
            xqc_moq_video_frame_ext_free(out_frame);
            out_frame = NULL;
        }
    }
    return 0;
}