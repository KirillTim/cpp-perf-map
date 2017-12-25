#include <string>
#include <iostream>
#include <fstream>

#include <unistd.h>

#include <jni.h>
#include <jvmti.h>
#include <vector>
#include <unordered_map>
#include <mach/notify.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/mach_init.h>

using namespace std;

static const int STRING_BUFFER_SIZE = 2000;

ofstream methods_map_file;
mutex methods_map_file_mutex; //not sure about ofstream buffers and flush atomicity
ofstream threads_map_file;
mutex threads_map_file_mutex;
ofstream log_file;

atomic<bool> in_live_phase;

static const int _thread_osthread_offset = 296; //TODO read from libjvm.dylib
static const int _osthread_id_offset = 96;

int os_thread_id(const void *vm_thread) {
    const char *os_thread = *(const char **) (((const char *) vm_thread) + _thread_osthread_offset);
    return *(int *) (os_thread + _osthread_id_offset);
}

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

void methods_map_file_write_entry(const void *code_addr, long code_size, const char *entry) {
    lock_guard<mutex> guard(methods_map_file_mutex);
    methods_map_file << my_formatter("0x%lx %ld %s", (unsigned long) code_addr, code_size, entry) << endl;
}

void threads_map_file_write_entry(const uint64_t native_tid, const int mach_id, const string& thread_name) {
    lock_guard<mutex> guard(threads_map_file_mutex);
    threads_map_file << my_formatter("%llu 0x%x %s", native_tid, mach_id, thread_name.c_str()) << endl;
}

void generate_single_entry(jvmtiEnv *jvmti, jmethodID method, const void *code_addr, jint code_size) {
    string entry = sig_string(jvmti, method);
    //log_file << "generate_single_entry " << entry << endl;
    methods_map_file_write_entry(code_addr, (long) code_size, entry.c_str());
}

static bool report_failed(const jvmtiError err, const string &error_msg) {
    if (err != JVMTI_ERROR_NONE) {
        log_file << error_msg << " (jvmtiError: " << err << ")" << endl;
        return true;
    }
    return false;
}

static JavaVM *_vm; //one for all threads

static JNIEnv *get_JNI() { //one per thread
    JNIEnv *jni;
    return _vm->GetEnv((void **) &jni, JNI_VERSION_1_6) == JVMTI_ERROR_NONE ? jni : nullptr;
}

//may only be called during the live phase
jvmtiThreadInfo get_thread_info(jvmtiEnv *jvmti, jthread thread) {
    jvmtiThreadInfo info{};
    jvmtiError err = jvmti->GetThreadInfo(thread, &info);
    if (err != JVMTI_ERROR_NONE) {
        cerr << "GetThreadInfo error: " << err << endl;
    }
    return info;
}

//may only be called during the live phase
string jthread_name(jvmtiEnv *jvmti, jthread thread) {
    jvmtiThreadInfo info = get_thread_info(jvmti, thread);
    string result = string(info.name);
    jvmti->Deallocate((unsigned char *) info.name);
    return result;
}

int get_os_tid(jthread thread) {
    JNIEnv *env = get_JNI();
    jclass threadClass = env->FindClass("java/lang/Thread");
    if (threadClass == nullptr) {
        cerr << "can't find class java/lang/Thread" << endl;
        return -1;
    }
    jfieldID eetop = env->GetFieldID(threadClass, "eetop", "J");
    if (eetop == nullptr) {
        cerr << "can't find field eetop" << endl;
        return -1;
    }
    const auto *vm_thread = (const void *) (uintptr_t) env->GetLongField(thread, eetop);
    return os_thread_id(vm_thread);
}

unordered_map<int, string> java_threads_mach_tid_to_name(jvmtiEnv *jvmti) {
    unordered_map<int, string> result;
    jint count = 0;
    jthread *threads = nullptr;
    jvmti->GetAllThreads(&count, &threads);
    cerr << "java threads count = " << count << endl;
    if (count == 0 || threads == nullptr) return result;
    for (int i = 0; i < count; i++) {
        int tid = get_os_tid(threads[i]);
        result[tid] = jthread_name(jvmti, threads[i]);
    }
    return result;
};

string pthread_name(pthread_t pthread) {
    char name[512] = {};
    pthread_getname_np(pthread, name, sizeof(name));
    return string(name);
}

uint64_t pthread_id(pthread_t pthread) {
    uint64_t pthread_id;
    pthread_threadid_np(pthread, &pthread_id);
    return pthread_id;
}

//may only be called during the live phase
void print_all_native_threads(jvmtiEnv *jvmti) {
    auto known_java_threads = java_threads_mach_tid_to_name(jvmti);
    mach_msg_type_number_t count;
    thread_act_array_t list;
    task_threads(mach_task_self(), &list, &count);
    for (int i = 0; i < count; i++) {
        pthread_t pthread = pthread_from_mach_thread_np(list[i]);
        int mach_tid = list[i];
        uint64_t native_tid = pthread_id(pthread);
        auto java_name = known_java_threads.find(mach_tid);
        string thread_name = java_name != known_java_threads.end() ? java_name->second : pthread_name(pthread);
        if (thread_name.empty()) {
            thread_name = "native thread id = " + to_string(native_tid);
        }
        threads_map_file_write_entry(native_tid, mach_tid, thread_name);
        string log_msg = my_formatter("native id: %llu, mach id: 0x%x, name: ",
                                      native_tid, mach_tid, thread_name.c_str());
        // cerr << log_msg << endl;
        log_file << log_msg << endl;
    }
    /*cerr << "java_threads_mach_tid_to_name:" << endl;
    for (auto &it : known_java_threads) {
        cerr << my_formatter("mach tid: %d (0x%x), name: %s", it.first, it.first, it.second.c_str()) << endl;
    }*/
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
    log_file << (unsigned long) time(nullptr) << " cbCompiledMethodLoad: " << sig_string(jvmti, method) << endl;
    generate_single_entry(jvmti, method, code_addr, code_size); //TODO: unfold inlined methods
}

static void JNICALL
cbDynamicCodeGenerated(jvmtiEnv *jvmti,
                       const char *name,
                       const void *address,
                       jint length) {
    log_file << (unsigned long) time(nullptr) << " "
             << my_formatter("cbDynamicCodeGenerated %s %lx", name, (unsigned long) address) << endl;
    methods_map_file_write_entry(address, (long) length, name);
}

void print_jthread(jvmtiEnv *jvmti, jthread thread, pthread_t pthread, const string &msg_prefix = "") {
    if (!in_live_phase) return;
    int mach_tid = pthread_mach_thread_np(pthread);
    uint64_t native_tid = pthread_id(pthread);
    string thread_name = jthread_name(jvmti, thread);
    threads_map_file_write_entry(native_tid, mach_tid, thread_name);
    string log_msg = my_formatter("%s native id: %llu, mach id: 0x%x, name: %s",
                                  msg_prefix.c_str(), native_tid, mach_tid, thread_name.c_str());
    //cerr << log_msg << endl;
    log_file << log_msg << endl;
}

static void JNICALL
cbThreadStart(jvmtiEnv *jvmti,
              JNIEnv *jni_env,
              jthread thread) {
    pthread_t pthread = pthread_self(); //callback is called on newly started thread
    print_jthread(jvmti, thread, pthread, "cbThreadStart");
}

void JNICALL
cbThreadEnd(jvmtiEnv *jvmti,
            JNIEnv *jni_env,
            jthread thread) {
    //if thread was renamed report the last name
    pthread_t pthread = pthread_self(); //callback is called on newly started thread
    print_jthread(jvmti, thread, pthread, "cbThreadEnd");
}

void JNICALL
cbVMInit(jvmtiEnv *jvmti,
         JNIEnv *jni_env,
         jthread thread) {
    cerr << "cbVMInit" << endl;
    log_file << "cbVMInit" << endl;
    in_live_phase = true;
    print_all_native_threads(jvmti);
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
    callbacks.ThreadStart = &cbThreadStart;
    callbacks.ThreadEnd = &cbThreadEnd;
    callbacks.VMInit = &cbVMInit;
    return jvmti->SetEventCallbacks(&callbacks, (jint) sizeof(callbacks));
}

vector<jvmtiEvent> EVENTS_LISTEN_TO{
        JVMTI_EVENT_COMPILED_METHOD_LOAD,
        JVMTI_EVENT_DYNAMIC_CODE_GENERATED,
        JVMTI_EVENT_THREAD_START,
        JVMTI_EVENT_THREAD_END,
        JVMTI_EVENT_VM_INIT
};

jvmtiError enable_notifications(jvmtiEnv *jvmti) {
    for (auto event: EVENTS_LISTEN_TO) {
        jvmtiError err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, event, nullptr);
        if (err != JVMTI_ERROR_NONE) return err;
    }
    return JVMTI_ERROR_NONE;
}

void disable_notifications(jvmtiEnv *jvmti) {
    for (auto event: EVENTS_LISTEN_TO) {
        jvmti->SetEventNotificationMode(JVMTI_DISABLE, event, nullptr);
    }
}

jvmtiError load_previous_events(jvmtiEnv *jvmti) {
    jvmtiError err = jvmti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD);
    if (err != JVMTI_ERROR_NONE) return err;
    err = jvmti->GenerateEvents(JVMTI_EVENT_DYNAMIC_CODE_GENERATED);
    return err;
}

static void shutdown(jvmtiEnv *jvmti) {
    if (in_live_phase) { //if still alive thread was renamed report the last name
        print_all_native_threads(jvmti);
    }
    disable_notifications(jvmti);
    log_file.close();
    lock_guard<mutex> m_guard(methods_map_file_mutex); //FIXME?
    methods_map_file.close();
    lock_guard<mutex> t_guard(threads_map_file_mutex);
    threads_map_file.close();
    cerr << "shutdown finished" << endl;
}

static void agent_main(JavaVM *vm, const char *options, void *reserved) {
    string clean_options = string(options == nullptr ? "" : options);
    log_file << "agent_main, options=" << clean_options << endl;
    cerr << "agent_main, options=" << clean_options << endl;
    _vm = vm;
    jvmtiEnv *jvmti;
    vm->GetEnv((void **) &jvmti, JVMTI_VERSION_1);
    if (clean_options.find("shutdown") != std::string::npos) {
        shutdown(jvmti);
        return;
    }
    if (!log_file.is_open()) {
        log_file.open(my_formatter("/tmp/perf-%d.new.log", getpid()).c_str());
        log_file << "agent_main, options=" << clean_options << endl;
    }
    string methods_map_filename = my_formatter("/tmp/perf-%d.map", getpid());
    methods_map_file.open(methods_map_filename.c_str());
    if (!methods_map_file.is_open()) {
        log_file << "can't open " << methods_map_filename << endl;
        return;
    }
    string threads_map_filename = my_formatter("/tmp/perf-%d-threads.map", getpid()); //TODO: unify
    threads_map_file.open(threads_map_filename.c_str());
    if (!threads_map_file.is_open()) {
        log_file << "can't open " << threads_map_filename << endl;
        return;
    }
    if (report_failed(enable_capabilities(jvmti), "enable_capabilities error")) return;
    if (report_failed(set_callbacks(jvmti), "set_callbacks error")) return;
    if (report_failed(enable_notifications(jvmti), "enable_notifications error")) return;
    if (report_failed(load_previous_events(jvmti), "load_previous_events error")) return;
    if (in_live_phase) print_all_native_threads(jvmti);
}


JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    log_file << "Agent_OnLoad" << endl;
    cerr << "Agent_OnLoad" << endl;
    in_live_phase = false;
    agent_main(vm, options, reserved);
    return 0;
}

JNIEXPORT jint JNICALL
Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    log_file << "Agent_OnAttach" << endl;
    cerr << "Agent_OnAttach" << endl;
    in_live_phase = true;
    agent_main(vm, options, reserved);
    return 0;
}
