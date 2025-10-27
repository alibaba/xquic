#ifndef _XQC_MOQ_DEFAULT_TRACK_H_
#define _XQC_MOQ_DEFAULT_TRACK_H_

#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_session.h"

typedef struct xqc_moq_default_track_s {
    xqc_moq_track_t    track;
    void               *user_data;
    uint64_t           next_group_id;
    uint64_t           next_object_id;
} xqc_moq_default_track_t;

/**
 * @brief 默认track的回调函数集合
 */
extern xqc_moq_track_ops_t xqc_moq_default_track_ops;

/**
 * @brief 初始化默认track
 */
void xqc_moq_default_track_init(xqc_moq_track_t *track);

/**
 * @brief 创建默认track
 */
xqc_moq_track_t *xqc_moq_default_track_create(xqc_moq_session_t *session, 
                                            char *track_namespace, 
                                            char *track_name, 
                                            xqc_moq_selection_params_t *params, 
                                            xqc_moq_track_role_t role);

/**
 * @brief 销毁默认track
 */
void xqc_moq_default_track_destroy(xqc_moq_track_t *track);

/**
 * @brief 发送默认track数据 每次创建新stream
 */
xqc_int_t xqc_moq_default_track_send(xqc_moq_track_t *track, uint8_t *data, size_t data_len);

/**
 * @brief 在指定stream上发送subgroup object（应用层可控制stream复用）
 * 
 * @param track         Track实例
 * @param stream        目标stream（NULL=创建新stream）
 * @param subgroup_id   Subgroup ID
 * @param data          数据
 * @param data_len      数据长度
 * @param is_first      是否是该subgroup的第一个object（需要发送SUBGROUP_HEADER）
 * 
 * @return 使用的stream（新创建或传入的stream），失败返回NULL
 */
xqc_moq_stream_t *xqc_moq_default_track_send_on_stream(
    xqc_moq_track_t *track,
    xqc_moq_stream_t *stream,
    uint64_t subgroup_id,
    uint8_t *data,
    size_t data_len,
    xqc_bool_t is_first);

/**
 * @brief 设置默认track的用户数据
 */
void xqc_moq_default_track_set_user_data(xqc_moq_track_t *track, void *user_data);

/**
 * @brief 获取默认track的用户数据
 */
void *xqc_moq_default_track_get_user_data(xqc_moq_track_t *track);

#endif /* _XQC_MOQ_DEFAULT_TRACK_H_ */ 