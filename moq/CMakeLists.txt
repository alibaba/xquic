if (XQC_ENABLE_MOQ)
    set(
        MOQ_SOURCES
        "moq/moq_transport/xqc_moq_message.c"
        "moq/moq_transport/xqc_moq_message_handler.c"
        "moq/moq_transport/xqc_moq_message_writer.c"
        "moq/moq_transport/xqc_moq_track.c"
        "moq/moq_transport/xqc_moq_proxy.c"
        "moq/moq_transport/xqc_moq_session.c"
        "moq/moq_transport/xqc_moq_stream.c"
        "moq/moq_transport/xqc_moq_stream_quic.c"
        "moq/moq_transport/xqc_moq_stream_webtransport.c"
        "moq/moq_transport/xqc_moq_subscribe.c"
        "moq/moq_transport/xqc_moq_utils.c"
        "moq/moq_transport/xqc_moq_bitrate_allocator.c"
        "moq/moq_transport/xqc_moq_fec.c"
        "moq/moq_transport/xqc_moq_fb_report.c"
        "moq/moq_transport/xqc_moq_feedback_tracker.c"
        "moq/moq_transport/xqc_moq_fb_report_gen.c"
        "moq/moq_transport/xqc_moq_feedback_track.c"
        "moq/moq_transport/xqc_moq_feedback_decision.c"
        "moq/moq_media/xqc_moq_catalog.c"
        "moq/moq_media/xqc_moq_container_loc.c"
        "moq/moq_media/xqc_moq_datachannel.c"
        "moq/moq_media/xqc_moq_media_track.c"
        "moq/moq_media/xqc_moq_av_frame_ext.c"
        "moq/cjson/cJSON.c"
        "moq/moq_media/dejitter/xqc_moq_av_dejitter.c"
        "moq/moq_media/dejitter/video/xqc_moq_jitter_buffer.c"
        "moq/moq_media/dejitter/video/xqc_moq_video_frame_buffer.c"
    )

    # add moq source (avoid CACHE to prevent stale source lists across reconfigure)
    set(XQC_SOURCE ${XQC_SOURCE} ${MOQ_SOURCES} PARENT_SCOPE)

    if(XQC_ENABLE_TESTING)
        add_subdirectory(demo)
        # add unit test for moq
        add_subdirectory(tests)
    endif(XQC_ENABLE_TESTING)

endif ()
