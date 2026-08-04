if (XQC_ENABLE_MOQ)
    set(
        MOQ_SOURCES
        "moq/moq_transport/xqc_moq_message.c"
        "moq/moq_transport/xqc_moq_message_handler.c"
        "moq/moq_transport/xqc_moq_namespace.c"
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
        "moq/moq_transport/version/xqc_moq_version.c"
        "moq/moq_transport/version/v5/xqc_moq_v5_profile.c"
        "moq/moq_transport/version/v5/xqc_moq_v5_message.c"
        "moq/moq_transport/version/v14/xqc_moq_v14_profile.c"
        "moq/moq_transport/version/v18/xqc_moq_v18_profile.c"
        "moq/moq_transport/draft18/xqc_moq_d18_auth.c"
        "moq/moq_transport/draft18/xqc_moq_d18_control.c"
        "moq/moq_transport/draft18/xqc_moq_d18_data.c"
        "moq/moq_transport/draft18/xqc_moq_d18_int.c"
        "moq/moq_transport/draft18/xqc_moq_d18_kv.c"
        "moq/moq_transport/draft18/xqc_moq_d18_params.c"
        "moq/moq_transport/draft18/xqc_moq_d18_properties.c"
        "moq/moq_transport/draft18/xqc_moq_d18_registry.c"
        "moq/moq_transport/draft18/xqc_moq_d18_request.c"
        "moq/moq_transport/draft18/xqc_moq_d18_setup.c"
        "moq/moq_transport/draft18/xqc_moq_d18_update.c"
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

    # add moq source
    set(
        XQC_SOURCE
        ${XQC_SOURCE}
        ${MOQ_SOURCES}
        CACHE INTERNAL "moq source files"
    )

    if(XQC_ENABLE_TESTING)
        add_subdirectory(demo)
        # add unit test for moq
        add_subdirectory(tests)
    endif(XQC_ENABLE_TESTING)

endif ()
