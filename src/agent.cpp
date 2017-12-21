#include <string>
#include <iostream>
#include <fstream>

#include <unistd.h>

#include <jni.h>
#include <jvmti.h>

using namespace std;

static const int STRING_BUFFER_SIZE = 1000;

ofstream methods_map_file;
ofstream log_file;

string my_formatter(const char *fmt, ...) {
    char buf[STRING_BUFFER_SIZE];
    va_list argptr;
    va_start(argptr, fmt);
    vsprintf(buf, fmt, argptr);
    va_end(argptr);
    return string(buf);
}

string class_name_from_sig(const string &sig) {
    string result = string(sig);
    if (result[0] == 'L') result = result.substr(1);
    result = result.substr(0, result.find(';'));
    for (char &i : result) {
        if (i == '/') i = '.';
    }
    return result;
}

static string sig_string(jvmtiEnv *jvmti, jmethodID method) { //TODO: jvmti resources wrapper class
    char *generic_method_sig = nullptr;
    char *generic_class_sig = nullptr;
    char *method_name = nullptr;
    char *msig = nullptr;
    char *csig = nullptr;
    jclass jcls;
    string result;
    if (!jvmti->GetMethodName(method, &method_name, &msig, &generic_method_sig)) {
        if (!jvmti->GetMethodDeclaringClass(method, &jcls)
            && !jvmti->GetClassSignature(jcls, &csig, &generic_class_sig)) {
            result = string(class_name_from_sig(csig)) + "." + string(method_name);
        }
    }
    if (generic_method_sig != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char *>(generic_method_sig));
    if (generic_class_sig != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char *>(generic_class_sig));
    if (method_name != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char *>(method_name));
    if (csig != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char *>(csig));
    if (msig != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char *>(msig));
    return result;
}

void methods_map_file_write_entry(const void *code_addr, unsigned int code_size, const char *entry) {
    methods_map_file << my_formatter("0x%lx 0x%x %s", (unsigned long) code_addr, code_size, entry) << endl;
}

void generate_single_entry(jvmtiEnv *jvmti, jmethodID method, const void *code_addr, jint code_size) {
    string entry = sig_string(jvmti, method);
    log_file << "generate_single_entry " << entry << endl;
    methods_map_file_write_entry(code_addr, (unsigned int)code_size, entry.c_str());
}

static bool report_failed(const jvmtiError err, const string &error_msg) {
    if (err != JVMTI_ERROR_NONE) {
        log_file << error_msg << " (jvmtiError: " << err << ")" << endl;
        return true;
    }
    return false;
}

static void JNICALL
cbCompiledMethodLoad(
        jvmtiEnv *jvmti,
        jmethodID method,
        jint code_size,
        const void *code_addr,
        jint map_length,
        const jvmtiAddrLocationMap *map,
        const void *compile_info) {
    log_file << (unsigned long)time(NULL) << " cbCompiledMethodLoad: " << sig_string(jvmti, method) << endl;
    generate_single_entry(jvmti, method, code_addr, code_size); //TODO: unfold inlined methods
}

static void JNICALL
cbDynamicCodeGenerated(jvmtiEnv *jvmti,
                       const char *name,
                       const void *address,
                       jint length) {
    log_file << (unsigned long)time(NULL) << " " << my_formatter("cbDynamicCodeGenerated %s %lx", name, (unsigned long) address) << endl;
    methods_map_file_write_entry(address, (unsigned int) length, name);
}

jvmtiError enable_capabilities(jvmtiEnv *jvmti) {
    jvmtiCapabilities capabilities{};
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_compiled_method_load_events = 1;
    return jvmti->AddCapabilities(&capabilities);
}

jvmtiError set_callbacks(jvmtiEnv *jvmti) {
    jvmtiEventCallbacks callbacks{};
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.CompiledMethodLoad = &cbCompiledMethodLoad; //TODO: CompiledMethodUnload
    callbacks.DynamicCodeGenerated = &cbDynamicCodeGenerated;
    return jvmti->SetEventCallbacks(&callbacks, (jint) sizeof(callbacks));
}

jvmtiError set_notification_mode(jvmtiEnv *jvmti) {
    jvmtiError err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr);
    if (err != JVMTI_ERROR_NONE) return err;
    err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, nullptr);
    return err;
}

jvmtiError load_previous_events(jvmtiEnv *jvmti) {
    jvmtiError err = jvmti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD);
    if (err != JVMTI_ERROR_NONE) return err;
    err = jvmti->GenerateEvents(JVMTI_EVENT_DYNAMIC_CODE_GENERATED);
    return err;
}

static void agent_main(JavaVM *vm, char *options, void *reserved) {
    log_file.open(my_formatter("/tmp/perf-%d.new.log", getpid()).c_str());
    log_file << "agent_main" << endl;
    cerr << "agent_main" << endl;
    string method_map_filename = my_formatter("/tmp/perf-%d.map.new", getpid());
    methods_map_file.open(method_map_filename.c_str());
    if (!methods_map_file.is_open()) {
        log_file << "can't open " << method_map_filename << endl;
        return;
    }
    jvmtiEnv *jvmti;
    vm->GetEnv((void **) &jvmti, JVMTI_VERSION_1);
    if (report_failed(enable_capabilities(jvmti), "enable_capabilities error")) return;
    if (report_failed(set_callbacks(jvmti), "set_callbacks error")) return;
    if (report_failed(set_notification_mode(jvmti), "set_notification_mode error")) return;
    if (report_failed(load_previous_events(jvmti), "load_previous_events error")) return;
}


JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    log_file << "Agent_OnLoad" << endl;
    agent_main(vm, options, reserved);
    return 0;
}

JNIEXPORT jint JNICALL
Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    log_file << "Agent_OnAttach" << endl;
    agent_main(vm, options, reserved);
    return 0;
}
