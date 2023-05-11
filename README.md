# FunJni  
 

## 前言：

在分析Apk的时候难免去分析So层，大多数native层都需要IDA调试，特别是分析数量很多的Apk的时候。我之前就想着，能不能对各种Naitive层进行监听。Apk放进去就可以实现自动化分析，包括调用了哪些方法，每个Java类里面保存了哪些数据。做了什么事情。特别是分析设备指纹的时候，Apk会采集非常多的设备信息。但是这些设备信息，无从下手，不知道应该从哪里改起，加上很多Apk都有混淆，分析起来是一件很费劲的事情。我们完全可以把一些关键信息，进行快速序列化，保存起来，对里面的东西直接搜索我们需要的内容即可即可 。

现在市面上有很多Java层的自吐工具，比如Hook，Java层的常见加密信息，以实现自吐，现在很多大厂基本都不会走Java层基础加密，大多数都是自己实现的加密方式，Java层最多只能算是辅助作用。几年之前还很好用，现在看起来有点鸡肋 。那么有没有什么比较好的分析Native的工具呢？

现在市面上常见的hook基本就是Frida和Xposed占大头，Frida常见的分析工具，比如Frida 的Jnitrace，Unidbg之类的 就很好用，根据Unidbg 的实现逻辑，targetSdk版本号检测，或者检测某个字符串的Hash的返回值 。

检测Frida的方法就更多了，各种反调试都是可以检测出来，比如文件，端口号，特征都是常见的anti点。

但是针对Xposed的检测却很难，需要先拿到Classloader，和一些特征才能判断是否被注入。特别是Lsposed，在Hunter里面也只能通过检测Libart的CRC，内存文件和本地文件的指令累加，判断是否相等，以检测Libart是否被修改，但是这种方式一般大厂也不敢轻易去上，很容易SIGN11。Lsposed因为是系统层注入，加上命名空间，还有本身Lsp的Classloader被隐藏了，在应用层很难去拿到比较好的特征点。这篇文章主要是介绍一下之前几年搞的各种小工具，做了个合计 。也方便各位以后能快速对各种Apk进行分析 。这篇文章读下来也会有不少收获 。



**另外代码会开源，还希望各位老板多多start ！**



## 主要功能&使用方式：

第一版本我只做了6个功能 。

- Java内存序列化
- JNIEnv监听，支持全量监听，防止动态下发SO绕过
- libc String处理函数监听
- JNIEnvRegisterNative监听
- Linker加载CallBack监听
- Java方法调用全量监听

第一版本算是搭了个架子，后面有时间的话会慢慢完善 。当然也欢迎各位大佬进行push和pull ，有好的建议可以在issues提想法 。

使用的话也很简单，Xposed模块，先选择需要Hook的Apk ，内存序列化和Native层Hook只能选一个 。如果没开启内存序列化的话，会弹窗。

推荐根据自己的需求去Hook指定的So 。比如libaaa.so ，只需要输入libaaa或者libaaa.so  即可，如果需要Hook监听多个So的话可以用|分割  。

如 libaaa.so|libbbb.so 即可 。下面会分别介绍一下具体的实现过程，不然只看代码学习效率很低。下面主要是一些实现的细节 。



### Xposed如何HookNaive层并且兼容5-13

这个很简单，直接把So注入即可，不同版本调用的api不同 。具体代码如下 。

```
public static void LoadSoForPath(String path, Object object) {
    try {
        CLog.e("load so path ->  " + path);
        if (Build.VERSION.SDK_INT >= 28) {
            String nativeLoad = (String) XposedHelpers.callMethod(Runtime.getRuntime(), "nativeLoad", path, object);
            CLog.e(nativeLoad == null ? "" : nativeLoad);
        } else {
            String doLoad = (String) XposedHelpers.callMethod(Runtime.getRuntime(), "doLoad", path, object);
            CLog.e(doLoad == null ? "" : doLoad);
        }
        CLog.i("load so for path success "+path);
    } catch (Throwable e) {
        CLog.e("load so for path " + e.getMessage());
    }
}
```

第一个参数是SO路径，这块有一个细节，卡住了不少人，就是这个方法的参数2，他是一个Classloader，这Classloader 表示当前注入So的Classloader ，在Native层不同的Classloader的作用域是不一样的，跟Dex一样，每个SO也是有属于自己的Classloader，因为Xposed的Classloader和当前进程Context的Classloader是不一样的。

如果你用当前进程的Context的Classloader进行注入，他会找不到Xposed加载的类，因为Classloader不一样 ，会一直提示class not find ，导致无法在Naitive层注册一个Native方法 。解决办法也很简单，直接用XposedHook类的.class.getClassLoader()即可 。

还有就是如何自动化区分被HookApk是64位还是32位。这块代码里面都会很详细的介绍和实现逻辑 ，具体参考代码。



### Java内存序列化：

什么是Java内存序列化，就是讲Java层整个虚拟机的全部Java实例转换成JSON字符串，保存到本地 。这个也是我经常用的功能之一 。

他有什么作用？比如一个很简单的CASE场景，我想知道一个大厂Apk设备指纹都保存在哪些Java类里面 ？都保存了什么东西 ？

直接让软件运行30秒以后( 这个时间可以根据自己的业务场景去控制)，扫描一下内存即可  。遍历的时间和Apk的大小有关系，Apk越大保存的对象越多，耗时越长 。

获取内存实例，实现原理也很简单，之前文章介绍过如何获取 https://bbs.kanxue.com/thread-269094.htm

这个Api是一个隐藏api  ，目前只做了 android 9- 11支持 。9-11是系统自带Api , 其他版本需要自己实现，我尝试在 5 - 9实现发现稳定性存在问题，所以在XposedJni里面做了判断，所以这个功能只有9-11支持 。

代码如下：

```
private void startSerialization(Context context) {
    try {
        //手动触发gc,清空多余实例
        System.gc();
        final File file = new File("/data/data/"
                + mTagPackageName + "/" + mProcessName + "_MemorySerializationInfo.txt");
        if (file.exists()) {
            file.delete();
        }
        file.createNewFile();
        //子线程和主线程共享数据
        ThreadUtils.runOnNonUIThread(() -> {
            ArrayList<Object> choose = ChooseUtils.choose(Object.class, true);
            int size = choose.size();
            CLog.e("memory object size -> " + size);
            for (int index = 0; index < size; index++) {
                Object obj = choose.get(index);
                String objStr = GsonUtils.obj2str(obj);
                if (objStr != null) {
                    String objClassName = obj.getClass().getName();
                    String infoStr = index + "/" + size + "[" + mProcessName + "]" + objClassName + " " + objStr + "\n";
                    //增加效率暂不打印进度
                    //printfProgress(size,index,context);
                    //ToastUtils.showToast(context,"MemorySerialization["+index+"/"+size+"]");
                    CLog.i(infoStr);
                    FileUtils.saveStringNoClose(infoStr, file);
                }
            }
            FileUtils.saveStringClose();
        }, 30 * 1000);
    } catch (Throwable e) {
        CLog.e("startSerialization error " + e);
    }
}
```

在子线程开启，将内存全部的Object实例拿到手以后，对每一个Object进行JSON字符串的转换，然后将转换以后的内容保存到本地 。包括Class的类名 。内容的JSON传等信息  。当然也可以根据自己需求取来，只获取需要的类即可 。比如我想查看内存里面全部的String变量 。可以将Object.class换成String.class即可 。方便快速分析和定位 。

效果如下基本一个大一点的Apk对象数量都超过15W以上，大约10分钟左右就可以遍历完毕，和手机配置有关系 。

```
2023-04-01 23:44:34.749 18522-19106/? I/Zhenxi: [Zhenxi] 287/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.749 18522-19106/? I/Zhenxi: [Zhenxi] 288/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.750 18522-19106/? I/Zhenxi: [Zhenxi] 289/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.752 18522-19106/? I/Zhenxi: [Zhenxi] 290/204804[进程名]android.system.StructStat {"st_atim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_atime":1680363817,"st_blksize":4096,"st_blocks":8,"st_ctim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_ctime":1680363817,"st_dev":64522,"st_gid":10236,"st_ino":137495,"st_mode":33200,"st_mtim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_mtime":1680363817,"st_nlink":1,"st_rdev":0,"st_size":148,"st_uid":10236}
2023-04-01 23:44:34.755 18522-19106/? I/Zhenxi: [Zhenxi] 291/204804[进程名]java.io.BufferedInputStream {"count":148,"marklimit":0,"markpos":-1,"pos":148}
2023-04-01 23:44:34.759 18522-19106/? I/Zhenxi: [Zhenxi] 292/204804[进程名]java.io.FileInputStream {"closeLock":{},"closed":true,"fd":{"descriptor":-1,"ownerId":0},"guard":{},"isFdOwner":true,"path":"/data/user/0/进程名/shared_prefs/RDeliveryHitSubTaskTagFile.xml","tracker":{"isOpen":true,"mode":"READ","opCount":1,"totalByteCount":16384}}
2023-04-01 23:44:34.772 18522-19106/? I/Zhenxi: [Zhenxi] 294/204804[进程名]java.lang.Object {}
2023-04-01 23:44:34.773 18522-19106/? I/Zhenxi: [Zhenxi] 295/204804[进程名]dalvik.system.CloseGuard {}
2023-04-01 23:44:34.774 18522-19106/? I/Zhenxi: [Zhenxi] 296/204804[进程名]libcore.io.IoTracker {"isOpen":true,"mode":"READ","opCount":1,"totalByteCount":16384}
2023-04-01 23:44:34.775 18522-19106/? I/Zhenxi: [Zhenxi] 297/204804[进程名]java.io.FileDescriptor {"descriptor":-1,"ownerId":0}
2023-04-01 23:44:34.776 18522-19106/? I/Zhenxi: [Zhenxi] 298/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.777 18522-19106/? I/Zhenxi: [Zhenxi] 299/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.778 18522-19106/? I/Zhenxi: [Zhenxi] 300/204804[进程名]android.system.StructTimespec {"tv_nsec":288510927,"tv_sec":1680363817}
2023-04-01 23:44:34.779 18522-19106/? I/Zhenxi: [Zhenxi] 301/204804[进程名]android.system.StructStat {"st_atim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_atime":1680363817,"st_blksize":4096,"st_blocks":8,"st_ctim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_ctime":1680363817,"st_dev":64522,"st_gid":10236,"st_ino":137495,"st_mode":33200,"st_mtim":{"tv_nsec":288510927,"tv_sec":1680363817},"st_mtime":1680363817,"st_nlink":1,"st_rdev":0,"st_size":148,"st_uid":10236}

... ...
```





### Jnitrace：

这个是我之前写的一个小工具，地址如下。

 https://github.com/w296488320/JnitraceForCpp

代码直接粘过来的 。今天有时间顺便改了改一些之前错误和多余的逻辑 。

主要监听的函数列表如下 。

```
HOOK_JNITRACE(env, CallObjectMethodV)
HOOK_JNITRACE(env, CallBooleanMethodV)
HOOK_JNITRACE(env, CallByteMethodV)
HOOK_JNITRACE(env, CallCharMethodV)
HOOK_JNITRACE(env, CallShortMethodV)
HOOK_JNITRACE(env, CallIntMethodV)
HOOK_JNITRACE(env, CallLongMethodV)
HOOK_JNITRACE(env, CallFloatMethodV)
HOOK_JNITRACE(env, CallDoubleMethodV)
HOOK_JNITRACE(env, CallVoidMethodV)

HOOK_JNITRACE(env, CallStaticObjectMethodV)
HOOK_JNITRACE(env, CallStaticBooleanMethodV)
HOOK_JNITRACE(env, CallStaticByteMethodV)
HOOK_JNITRACE(env, CallStaticCharMethodV)
HOOK_JNITRACE(env, CallStaticShortMethodV)
HOOK_JNITRACE(env, CallStaticIntMethodV)
HOOK_JNITRACE(env, CallStaticLongMethodV)
HOOK_JNITRACE(env, CallStaticFloatMethodV)
HOOK_JNITRACE(env, CallStaticDoubleMethodV)
HOOK_JNITRACE(env, CallStaticVoidMethodV)

HOOK_JNITRACE(env, GetObjectField)
HOOK_JNITRACE(env, GetBooleanField)
HOOK_JNITRACE(env, GetByteField)
HOOK_JNITRACE(env, GetCharField)
HOOK_JNITRACE(env, GetShortField)
HOOK_JNITRACE(env, GetIntField)
HOOK_JNITRACE(env, GetLongField)
HOOK_JNITRACE(env, GetFloatField)
HOOK_JNITRACE(env, GetDoubleField)
HOOK_JNITRACE(env, GetStaticObjectField)
HOOK_JNITRACE(env, GetStaticBooleanField)
HOOK_JNITRACE(env, GetStaticByteField)
HOOK_JNITRACE(env, GetStaticCharField)
HOOK_JNITRACE(env, GetStaticShortField)
HOOK_JNITRACE(env, GetStaticIntField)
HOOK_JNITRACE(env, GetStaticLongField)
HOOK_JNITRACE(env, GetStaticFloatField)
HOOK_JNITRACE(env, GetStaticDoubleField)
HOOK_JNITRACE(env, NewStringUTF)
HOOK_JNITRACE(env, GetStringUTFChars)
HOOK_JNITRACE(env, FindClass)
HOOK_JNITRACE(env, ToReflectedMethod)
HOOK_JNITRACE(env, FromReflectedMethod)
HOOK_JNITRACE(env, GetFieldID)
HOOK_JNITRACE(env, GetStaticFieldID)
HOOK_JNITRACE(env, NewObjectV)
```

都是一些常见的JNI交互函数，Hook以后在调用之前和调用之后将jobject 进行toString打印即可。这块需要注意的是打印可变参数和栈溢出问题，

因为我们也需要调用JNI函数，需要判断哪些SO监听，哪些不需要监听 ，剩下的就是代码细节实现了 。因为打印日志量比较多，所以需要将Log一些信息保存到本地文件里面 。代码实现也很简单，封装了大量的宏，减少工作量 。

```
//jobject CallObjectMethod(JNIEnv*, jobject, jmethodID, va_list args);
JNI_HOOK_DEF(jobject, CallObjectMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
             va_list args)
    DL_INFO
    IS_MATCH
            GET_JOBJECT_INFO(env, obj, "CallObjectMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, args, false)
            jobject ret = orig_CallObjectMethodV(env, obj, jmethodId, args);
            getJObjectInfoInternal(env, ret, "result object :", true, nullptr);
            return ret;
        }
    }
    return orig_CallObjectMethodV(env, obj, jmethodId, args);
}

//void CallVoidMethod(jobject obj, jmethodID methodID, va_list args)
JNI_HOOK_DEF(void, CallVoidMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
             va_list args)
    DL_INFO
    IS_MATCH
            GET_JOBJECT_INFO(env, obj, "CallVoidMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, args, false)
        }
    }
    return orig_CallVoidMethodV(env, obj, jmethodId, args);
}
...
```

打印效果截取如下 ：

```
2023-04-01 23:47:27.494 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : vb_platformInfo_channel_id
2023-04-01 23:47:27.494 21432-21457/? I/Zhenxi: [文件名] args 0   1  1
2023-04-01 23:47:27.495 21432-21432/? I/Zhenxi: [文件名] GetStringUTFChars : android.hardware.Sensor
2023-04-01 23:47:27.495 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : key_guid
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBIPExchanger_InnerInitTask
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : isMainProc proc:包名:cache packageName:包名
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBPBService-6447
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : NXNetwork_Transport_HttpImpl
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : [GetCarrierIPRequest]-1  connectStart():/60.28.219.101:443
2023-04-01 23:47:27.495 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBPBService-6447
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : QAD
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : setQAdMediaPlayerCreator() QAD_TVKPlayer注册成功
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : TVK-HighPriorityThread1
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBNetStateService_VBNetTypeHelper
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : getNetworkInfo network capability validated:true
2023-04-01 23:47:27.496 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBPBService-6447
2023-04-01 23:47:27.496 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : creator_account_info_key
2023-04-01 23:47:27.497 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : vb_platformInfo_channel_id
2023-04-01 23:47:27.497 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : key_guid
2023-04-01 23:47:27.498 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : creator_account_info_key
2023-04-01 23:47:27.498 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : vb_platformInfo_channel_id
2023-04-01 23:47:27.500 21432-21709/? I/Zhenxi: [文件名] GetStringUTFChars : key_guid
2023-04-01 23:47:27.502 21432-21486/? I/Zhenxi: [文件名] GetStringUTFChars : public_io_pool-6479
2023-04-01 23:47:27.503 21432-21796/? I/Zhenxi: [文件名] args 3   17  17
2023-04-01 23:47:27.503 21432-21796/? I/Zhenxi: [文件名] invoke method result Boolean : true
2023-04-01 23:47:27.504 21432-21432/? I/Zhenxi: <<<<<------------------CallBooleanMethodV start--------------------->>>>>
2023-04-01 23:47:27.506 21432-21432/? I/Zhenxi: [文件名] invoke this object  android.hardware.Sensor  {Sensor name="linear_acceleration", vendor="qualcomm", version=1, type=0, maxRange=156.98999, resolution=0.01, power=0.515, minDelay=5000}
2023-04-01 23:47:27.507 21432-21432/? I/Zhenxi: [文件名] invoke method  private boolean android.hardware.Sensor.setType(int)
2023-04-01 23:47:27.508 21432-21432/? I/Zhenxi: [文件名] args 0   10  10
2023-04-01 23:47:27.508 21432-21432/? I/Zhenxi: [文件名] invoke method result Boolean : true
2023-04-01 23:47:27.509 21543-21672/? I/Zhenxi: [文件名] GetStringUTFChars : VBNetStateService_VBNetTypeHelper
2023-04-01 23:47:27.509 21432-21459/? I/Zhenxi: [文件名] invoke this object  android.view.ViewRootImpl$W  android.view.ViewRootImpl$W@43c430d

...
```





### libcString处理函数

主要处理函数如下 

```
void stringHandler::init() {
    void *handle = dlopen("libc.so", RTLD_NOW);

    if (handle == nullptr) {
        LOG(ERROR) << "strhadler get handle == null   ";
        return;
    }


    HOOK_SYMBOL_DOBBY(handle, strstr)
    HOOK_SYMBOL_DOBBY(handle, strcmp)
    HOOK_SYMBOL_DOBBY(handle, strcpy)
    HOOK_SYMBOL_DOBBY(handle, strdup)

    HOOK_SYMBOL_DOBBY(handle, strxfrm)
    HOOK_SYMBOL_DOBBY(handle, strtok)

//    HOOK_SYMBOL_DOBBY(handle, memcpy)
//    HOOK_SYMBOL_DOBBY(handle, read)
//    HOOK_SYMBOL_DOBBY(handle, write)

//    HOOK_SYMBOL_DOBBY(handle, sprintf);
//    HOOK_SYMBOL_DOBBY(handle, printf);
//    HOOK_SYMBOL_DOBBY(handle, snprintf);
//    HOOK_SYMBOL_DOBBY(handle, vsnprintf);
```



其他大部分底层都是这几个函数，也是将不同函数的参数进行hook和拦截 。在处理之前和处理之后进行打印  。一般不注重安全的程序员，都会用系统的函数进行比较和替换，而非自己去实现，比如比较当前进程是否正在被调试，我们只需要打印比较传入的参数的内容 。找到以后直接打印调用栈和函数地址 。

可以很快速的定位反调试的位置 。还有其他地方， 也可以通过这些函数也可以获取到很多有用的信息 。

这块我想处理一下C++ STD里面的string ，因为string 会被inline ，所以只能去宿主so里面去hook 。就一直没来得及时间去处理后面有时间补上 。

打印效果如下：

```
2023-04-01 23:51:02.119 22893-22970/? I/Zhenxi: [文件名]strcmp() arg1 -> /storage/emulated/0/DCIM/.tmfs/.turing.dat  arg2-> /storage/emulated/0/.turing.dat
2023-04-01 23:51:02.119 22893-22970/? I/Zhenxi: [文件名]strcmp() arg1 -> /storage/emulated/0/DCIM/.tmfs/.turing.dat  arg2-> /storage/emulated/0/DCIM/.tmfs/.turing.dat
2023-04-01 23:51:02.119 22893-22970/? I/Zhenxi: [文件名]strcmp() arg1 -> /storage/emulated/0/.turing.dat  arg2-> /storage/emulated/0/.turing.dat
2023-04-01 23:51:02.120 22893-22970/? I/Zhenxi: [文件名]strcmp() arg1 -> /data/user/0/com.xxxxxx.vvvv/app_turingdfp/1/.turing.dat  arg2-> /storage/emulated/0/.turing.dat
2023-04-01 23:51:02.120 22893-22970/? I/Zhenxi: [文件名]strcmp() arg1 -> /data/user/0/com.xxxxxx.vvvv/app_turingdfp/1/.turing.dat  arg2-> /storage/emulated/0/DCIM/.tmfs/.turing.dat
2023-04-01 23:51:02.136 23013-23041/? I/Zhenxi: [文件名]strcpy() arg1 -> android.os.Handler$MessengerImpl  arg2-> android.os.Handler$MessengerImplresult -> android.os.Handler$MessengerImpl
2023-04-01 23:51:02.136 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> org.chromium.android_webview.AwContents  arg2-> android.os.Handler$MessengerImpl
2023-04-01 23:51:02.136 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> android.app.ActivityThread$ApplicationThread  arg2-> android.os.Handler$MessengerImpl
2023-04-01 23:51:02.136 23013-23041/? I/Zhenxi: [文件名]strcpy() arg1 -> android.os.IMessenger$Stub  arg2-> android.os.IMessenger$Stubresult -> android.os.IMessenger$Stub
2023-04-01 23:51:02.137 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> org.chromium.android_webview.AwContents  arg2-> android.os.IMessenger$Stub
2023-04-01 23:51:02.137 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> android.app.ActivityThread$ApplicationThread  arg2-> android.os.IMessenger$Stub
2023-04-01 23:51:02.137 23013-23041/? I/Zhenxi: [文件名]strcpy() arg1 -> android.os.Binder  arg2-> android.os.Binderresult -> android.os.Binder
2023-04-01 23:51:02.137 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> org.chromium.android_webview.AwContents  arg2-> android.os.Binder
2023-04-01 23:51:02.138 23013-23041/? I/Zhenxi: [文件名]strcmp() arg1 -> android.app.ActivityThread$ApplicationThread  arg2-> android.os.Binder
....
```





### JNIEnvRegisterNative注册监听：

这个实现也很简单，直接hook artmethod里面的RegisterNative ,然后调用prettyMethod函数指针打印artmethod信息 。

我这块在在回调里面打印了，**方法基础签名信息 ，绝对地址，相对地址，所属efl文件** 。这个方法里面没做判断，会打印注册全部的信息 。

```
HOOK_DEF(void*, RegisterNative, void *thiz, void *native_method) {
    string basicString = invokePrintf_org_PrettyMethodSym(thiz, true);
    if (isSave) {
        *invokeOs << basicString.append("\n");
    }
    Dl_info info;
    dladdr(native_method, &info);
    size_t relative_offset =
            reinterpret_cast<size_t>(native_method) - reinterpret_cast<size_t>(info.dli_fbase);

    LOG(INFO) <<"REGISTER_NATIVE " << basicString.c_str() << " absolute address(内存地址) -> "
                        << native_method << "  relative offset(相对地址) "<<(void*)relative_offset
                        <<"所属ELF文件 ["<<getFileNameForPath(info.dli_fname)+"]";

    return orig_RegisterNative(thiz, native_method);
}
```

打印效果如下：

```
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE int com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.clearCache(java.lang.String, java.lang.String, int)
     absolute address(内存地址) -> 0x77787377fc  relative offset(相对地址) 0x3357fc所属ELF文件 [mmmm.so]
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE long com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.verifyOfflineCacheSync(java.lang.String, int, java.lang.String, java.lang.String)
     absolute address(内存地址) -> 0x7778737908  relative offset(相对地址) 0x335908所属ELF文件 [mmmm.so]
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE void com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.setPlayerState(int, int)
     absolute address(内存地址) -> 0x7778737a68  relative offset(相对地址) 0x335a68所属ELF文件 [mmmm.so]
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE void com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.updateTaskInfo(int, java.lang.String, java.lang.String)
     absolute address(内存地址) -> 0x7778737a74  relative offset(相对地址) 0x335a74所属ELF文件 [mmmm.so]
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE void com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.updatePlayerPlayMsg(int, int, int, int)
     absolute address(内存地址) -> 0x7778737b78  relative offset(相对地址) 0x335b78所属ELF文件 [mmmm.so]
2023-04-01 23:53:12.617 24017-24247/? I/Zhenxi: REGISTER_NATIVE boolean com.xxxxxx.bbbb.core.downloadproxy.jni.TPDownloadProxyNative.isNativeReadyForWork()
     absolute address(内存地址) -> 0x7778737b8c  relative offset(相对地址) 0x335b8c所属ELF文件 [mmmm.so]
...
```



### LinkerCallBack回调:

这个方法里面主要是Hook了 linker 底层open的方法，在Linker刚刚将内存加载到内存里还没有进行初始化的时候，得到一个回调。

也是详细打印了各种信息 ，比如**SO开始地址，结束地址，ELF的长度**。可以在这块进行SO的dump和保存，这个时机点还有一个作用就是做监听和资源文件。

举个栗子，在对游戏源码进行脱壳和修复的时候，比如LUA文件的dump修复，是需要先Hook buffloader函数的 ，也就是在这这个时机点进行Hook 。So刚刚加载到内存里面，还没有进行源码的加载，即刻进行Hook ，这么一来他加载的文件都会被拦截。实际太早或者太晚，都可能导致dump的不全 。

这块也是暴露出来一个时机点，方便Hook  。

```
void onSoLoadedAfter(const char *filename,void *ret){
    auto mapInfo = getSoBaseAddress(filename);
    char buffer[PATH_MAX];
    sprintf(buffer, "linker load %s  start-> 0x%zx  end-> 0x%zx  size -> %lu",
            filename, mapInfo.start, mapInfo.end, (mapInfo.end - mapInfo.start));
    if (isSave) {
        if (hookStrHandlerOs != nullptr) {
            (*hookStrHandlerOs) << buffer;
        }
    }
    LOGI("%s ", buffer);
}
```

打印效果如下：

```
2023-04-01 23:53:12.023 24017-24429/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/yyyy.so  start-> 0x77a275b000  end-> 0x77a27ad000  size -> 335872 
2023-04-01 23:53:12.140 24017-24247/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/kkkk.so  start-> 0x778f68b000  end-> 0x779054c000  size -> 15470592 
2023-04-01 23:53:12.172 24017-24424/? I/Zhenxi: linker load libnetd_client.so  start-> 0x78ff86c000  end-> 0x78ff875000  size -> 36864 
2023-04-01 23:53:12.362 24017-24429/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/libckeygeneratorV2.so  start-> 0x7783a48000  end-> 0x7783aeb000  size -> 667648 
2023-04-01 23:53:12.410 24017-24429/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/libxps_ws.so  start-> 0x778159a000  end-> 0x77816ef000  size -> 1396736 
2023-04-01 23:53:12.611 24017-24247/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/libDownloadProxy.so  start-> 0x7778402000  end-> 0x7778d73000  size -> 9900032 
2023-04-01 23:53:12.700 24017-24247/? I/Zhenxi: linker load libc.so  start-> 0x7900557000  end-> 0x7900653000  size -> 1032192 
2023-04-01 23:53:12.729 23903-23903/? I/Zhenxi: linker load /data/app/~~KJajvMQT0WLC5kpaiv75pA==/baoming-ZPiDMFjwVCA12Ot9z_btog==/lib/arm64/kkkk.so  start-> 0x772d186000  end-> 0x772e047000  size -> 15470592 
...
```



### Java 调用方法监听：

主要是Hook了artmethod的invoke方法，一切的java方法底层都会走这个方法，包括脱壳也是修改的这个方法获取被抽取的指令，然后对Dex进行重构 。

我想尝试在这个方法里面对参数进行打印，但是失败了，在源码里面很好修改，但是通过Hook的话很多函数拿不到 ，加上一些核心的方法被编译器inline了，很不好操作和处理，就没继续关注了 。如果你有想法和思路可以提issues 或者提交代码 。这个方法不建议开启，个人用的很少，主要打印量太大了，一秒几千条日志 。他会打印系统的一些Java方法 ，所以很卡顿 ，不过如果你想做监听和记录 ，分析一些隐藏Api很有用  。callback实现如下 。

```
HOOK_DEF(void*, invoke, void *thiz, void *self, uint32_t *args, uint32_t args_size, void *result,
         const char *shorty) {

    string basicString = invokePrintf_org_PrettyMethodSym(thiz, true);

    LOG(INFO) << "invoke method info -> " << basicString;

    if (isSave) {
        *invokeOs << basicString.append("\n");
    }
    return orig_invoke(thiz, self, args, args_size, result, shorty);
}
```







### nativeLib :

这个是一个我自己封装的一个native库，里面有很多常用的方法，都进行了封装 ，删除了一些改机和没用的模块，留了一些常用的模块 。

主要是下面几个比较常用的 ，也方便后续开发和维护 。 

- hook模块
- 符号查找模块（支持非导出函数）
- 常用工具类模块
- raw_syscall模块
- libpath



比如常见的hook操作 。如何inlinehook少于四个字节的方法，如何插装hook和如何异常hook 。这些都不需要关注，导入头文件以后直接 。

```
HookUtils::Hooker(xxx,(void *) xxx,(void **) &new_xxx);
```

一键hook即可  。底层封装分三步实现，先dobby hook ，失败了则使用异常hook， 最后dobby插装 。代码如下

```
bool HookUtils::Hooker(void *dysym, void *newrep, void **org) {
    if (dysym == nullptr) {
        LOG(ERROR) << "dobby hook org == null ";
        return false;
    }
    if (hookedList == nullptr) {
        hookedList = new list<void *>();
    }

    //如果这个地址已经被Hook了 。也有可能返回失败 。dobby 会提示 already been hooked 。
    for (void *ptr: *hookedList) {
        if (ptr == dysym) {
            //如果保存了这个地址,说明之前hook成功过,我们也认为hook成功
            return true;
        }
    }

    bool ret = DobbyHook(dysym,
                         reinterpret_cast<dobby_dummy_func_t>(newrep),
                         reinterpret_cast<dobby_dummy_func_t *>(org)) == RT_SUCCESS;
    if (ret) {
        //LOG(ERROR) << "hook utils hook success !" ;
        //将地址添加到已经hook的列表,防止这个地址被多次hook
        hookedList->push_back(dysym);
        return true;
    }

    //如果dobby hook失败了,采用sandhook异常hook进行补救,
    LOG(ERROR) << "zhenxi runtime inlinehook start sandhook InlineHookImpl  ";
    ret = SandHook::Inline::InlineHookImpl(dysym, newrep, org);
    if (ret) {
        hookedList->push_back(dysym);
        return true;
    }

    LOG(ERROR)
            << ">>>>>>>>>>>>>>> sandhook inlinehook hook error,start dobby branch_trampoline hook ";
    //如果sandhook sign hook 也失败了,我们采用dobby附近插装去hook
    dobby_enable_near_branch_trampoline();
    //二次hook
    ret = DobbyHook(dysym,
                    reinterpret_cast<dobby_dummy_func_t>(newrep),
                    reinterpret_cast<dobby_dummy_func_t *>(org)) == RT_SUCCESS;
    //关闭附近插装
    dobby_disable_near_branch_trampoline();
    if (!ret) {
        LOG(ERROR) << "!!!!!!!!!!!!!!!  HookUtils hook error   ";
        return false;
    }
    hookedList->push_back(dysym);
    return ret;

}
```

其他的不一一概述了，感兴趣的可以去看代码 。项目主要采用C++ 20编译的，需要NDK 23以上版本支持 。





