//
// Created by Neho on 2022/8/22.
//

#include <jni.h>

#include "include/xqc_common.h"
#include "include/global_common.h"
#include "include/client_send_main.h"

static JavaVM *jvm;

void
callback_data(void* java_level_obj, const char * body_content, size_t body_len){

    LOGD("entry callback_data");
    // 首先找到原来的env
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);

    // 找到SendNatvie class
    jclass cls = (*env)->GetObjectClass(env, java_level_obj);
    // 得到对象实例
    jobject send_native_instance = (*env)->NewGlobalRef(env, java_level_obj);
    // 通过方法签名找到对应的callback方法
    jmethodID callback_id = (*env)->GetMethodID(env, cls, "callback", "([B)V");

    if(callback_id == NULL) {
        LOGE("(*env)->GetMethodID error, can't find method");
        return;
    }

    // str to byte[]
    jbyteArray body_content_byte_array = (*env)->NewByteArray(env, (jsize) body_len);
    (*env)->SetByteArrayRegion(env, body_content_byte_array, 0, (jsize) body_len, (jbyte*)body_content);

    // 回调
    (*env)->CallVoidMethod(env, send_native_instance, callback_id, body_content_byte_array);

    // 释放内存
    (*env)->DeleteLocalRef(env, body_content_byte_array);
    (*env)->DeleteGlobalRef(env, send_native_instance);
    (*env)->DeleteLocalRef(env, cls);

}

jint get_int_from_env(JNIEnv *env, jobject param, const char *field) {
    jclass sendParamsClass = (*env)->GetObjectClass(env, param);
    jfieldID jfieldId = (*env)->GetFieldID(env, sendParamsClass, field, "I");
    if (!jfieldId) {
        return 0;
    }
    jint data = (*env)->GetIntField(env, param, jfieldId);
    (*env)->DeleteLocalRef(env, sendParamsClass);
    return data;
}

jstring get_string_from_env(JNIEnv *env, jobject send_config, char *field) {
    jclass send_config_class = (*env)->GetObjectClass(env, send_config);
    jfieldID field_id =(*env)->GetFieldID(env, send_config_class, field, "Ljava/lang/String;");
    if(!field_id) {
        return NULL;
    }
    jstring str = (jstring) (*env)->GetObjectField(env, send_config, field_id);
    (*env)->DeleteLocalRef(env, send_config_class);
    return str;
}

client_user_data_params_t * make_params_default(client_user_data_params_t *ret) {
    ret->log_level = XQC_LOG_DEBUG;
    ret->g_echo_check = 0;
    ret->g_req_max = 1;
    ret->g_is_get = 0;
    ret->g_send_body_size = 1024 * 1024;
    snprintf(ret->g_scheme, sizeof("https"), "%s", "https");
    snprintf(ret->g_host, sizeof("test.xquic.com"), "%s", "test.xquic.com");
    snprintf(ret->g_url_path, sizeof("/path/resource"), "%s", "/path/resource");
    ret->g_header_num = 6;
    snprintf(ret->server_addr, sizeof("47.111.106.80"), "%s", "47.111.106.80");
    ret->server_port = 8443;
    ret->transport = 0;
    ret->g_conn_timeout = 1;
    ret->g_ipv6 = 0;
    ret->cc = CC_TYPE_BBR;
    ret->pacing_on = 0;
    ret->req_paral = 1;
    ret->force_cert_verificaion = 0;
    ret->g_force_1rtt = 0;
    ret->no_encryption = 0;

    return ret;
}

client_user_data_params_t * get_user_params(JNIEnv *env, jobject send_config, jobject send_native_obj) {
    jstring jserver_addr = get_string_from_env(env, send_config, "serverAddress");
    const char * server_addr = (jserver_addr != NULL) ? (*env)->GetStringUTFChars(env, jserver_addr, 0) : "";
    jint server_port = get_int_from_env(env, send_config, "serverPort");
    jint req_paral = get_int_from_env(env, send_config, "requestParal");
    jint g_req_max = get_int_from_env(env, send_config, "reqtesMax");
    jint g_send_body_size = get_int_from_env(env, send_config, "bodySize");
    jint force_cert_verificaion = get_int_from_env(env, send_config, "forceCertVerification");
    jstring url = get_string_from_env(env, send_config, "url");

    jint pacing_on = get_int_from_env(env, send_config, "pacingOn");
    jint g_force_1rtt = get_int_from_env(env, send_config, "force1RTT");
    jint g_ipv6 = get_int_from_env(env, send_config, "ipv6");
    jint no_encryption = get_int_from_env(env, send_config, "noCrypt");

    jstring jcc_type = get_string_from_env(env, send_config, "CCType");
    const char * cc_type = (jcc_type != NULL) ? (*env)->GetStringUTFChars(env, jcc_type, 0) : "";
    jstring jrequest_type = get_string_from_env(env, send_config, "requestType");
    const char * request_type = (jrequest_type != NULL) ? (*env)->GetStringUTFChars(env, jrequest_type, 0) : "";

    if (!url || !server_addr) {
        LOGE("xquicConnect error url == NULL, no target server");
        return NULL;
    }

    // malloc 分配空间
    client_user_data_params_t *ret = malloc(sizeof(client_user_data_params_t));

    // 初始值（默认值先附上）
    ret = make_params_default(ret);
    // 更新用户的值
    snprintf(ret->server_addr, 64, "%s", server_addr);
    LOGD("new server addr: %s", ret->server_addr);
    ret->server_port = server_port;
    ret->req_paral = req_paral;
    ret->g_req_max = g_req_max;
    ret->g_send_body_size = g_send_body_size;
    ret->force_cert_verificaion = force_cert_verificaion;
    ret->url = url;

    ret->pacing_on = pacing_on;
    ret->g_force_1rtt = g_force_1rtt;
    ret->g_ipv6 = g_ipv6;
    ret->no_encryption = no_encryption;

    if (strcmp(cc_type, "BBR") == 0) {
        ret->cc = CC_TYPE_BBR;
    } else if (strcmp(cc_type, "CUBIC") == 0) {
        ret->cc = CC_TYPE_CUBIC;
    } else if (strcmp(cc_type, "RENO") == 0) {
        ret->cc = CC_TYPE_RENO;
    } else {  // default, TODO: add BBR2
        LOGE("CCTYPE error, unidentified cc type");
    }

    ret->g_is_get = (strcmp(request_type, "GET") == 0) ? 1 : 0;


    // callback 回调函数
    ret->callback_body_content = callback_data;
    ret->java_level_obj = send_native_obj;


    return ret;
}



int send_main(JNIEnv *env, jobject this, jobject send_config) {
    client_user_data_params_t *user_params = get_user_params(env, send_config, this);
    if (user_params == NULL) {
        return -1;
    }

    return client_send(user_params);
}

// 动态注册的方法
JNINativeMethod gMethods[] ={
        {"Send", "(Lnativejni/SendConfig;)I", (void*)send_main},
};

// 注册函数
int registerNativeMethods(JNIEnv *env) {    //JNIEnv : JavaVM 在线程中的代表, 每一个线程都有一个, JNI 中可能有非常多个 JNIEnv;
    jclass cls = (*env) -> FindClass(env,"nativejni/SendNative");
    if((*env) -> RegisterNatives(env,cls,gMethods, sizeof(gMethods) / sizeof(gMethods[0])))
        return -1;
    return 0;
}

jint JNI_OnLoad(JavaVM *vm, void *unused) {
    jvm = vm;
    JNIEnv* env;
    if ((*vm) -> GetEnv(vm,(void**)&env,JNI_VERSION_1_4) != JNI_OK || registerNativeMethods(env) != JNI_OK)
        return JNI_ERR;
    return JNI_VERSION_1_4;
}


