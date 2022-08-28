//
// Created by Neho on 2022/8/23.
//

#ifndef XQUICANDROIDDEMO_GLOBAL_COMMON_H
#define XQUICANDROIDDEMO_GLOBAL_COMMON_H


#include <stdlib.h>
#include <string.h>

#define TAG "<-JNI->"
#include <android/log.h>
#define LOGW(...)    __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...)    __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGI(...)    __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...)    __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define DEBUG LOGD("fun:%s,line %d \n", __FUNCTION__, __LINE__);

#endif //XQUICANDROIDDEMO_GLOBAL_COMMON_H