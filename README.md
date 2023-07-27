# Awesome Fuzzing Resources

记录一些fuzz的工具和论文。[https://github.com/secfigo/Awesome-Fuzzing](https://github.com/secfigo/Awesome-Fuzzing)可能很多人看过，我也提交过一些Pull Request，但是觉得作者维护不是很勤快：有很多过时的信息，新的信息没有及时加入，整体结构也很乱。干脆自己来整理一个。欢迎随时提出issue和Pull Request。

## books

[The Fuzzing Book](https://www.fuzzingbook.org/)

[Fuzzing for Software Security Testing and Quality Assurance(2nd Edition)](https://www.amazon.com/Fuzzing-Software-Security-Testing-Assurance/dp/1608078507)

[Fuzzing Against the Machine: Automate vulnerability research with emulated IoT devices on Qemu](https://www.amazon.com/Fuzzing-Against-Machine-Automate-vulnerability-ebook/dp/B0BSNNBP1D)

## fuzzer

zzuf(https://github.com/samhocevar/zzuf)

radamsa(https://gitlab.com/akihe/radamsa)

certfuzz(https://github.com/CERTCC/certfuzz)

这几个都是比较有代表性的dumb fuzzer，但是我们在实际漏洞挖掘过程中也是可以先用dumb fuzzer搞一搞的，之后再考虑代码覆盖率的问题。

AFL(https://github.com/google/AFL)

前project zero成员@lcamtuf编写，可以说是之后各类fuzz工具的开山鼻祖，甚至有人专门总结了由AFL衍生而来的各类工具：https://github.com/Microsvuln/Awesome-AFL

honggfuzz(https://github.com/google/honggfuzz)

libFuzzer(http://llvm.org/docs/LibFuzzer.html)

AFL/honggfuzz/libFuzzer是三大最流行的覆盖率引导的fuzzer并且honggfuzz/libFuzzer的作者也是google的。很多人在开发自己的fuzzer的时候都会参考这三大fuzzer的代码。

oss-fuzz(https://github.com/google/oss-fuzz)

google发起的针对开源软件的fuzz，到2023年2月OSS-Fuzz已经发现了850个项目中的超过8900个漏洞和28000个bug。

fuzztest(https://github.com/google/fuzztest)

libfuzzer作者不再维护之后开的一个新坑，功能更强大更容易像单元测试那样集成。

winafl(https://github.com/googleprojectzero/winafl)

project zero成员@ifratric将AFL移植到Windows上对闭源软件进行覆盖率引导的fuzz，通过DynamoRIO实现动态插桩。

Jackalope(https://github.com/googleprojectzero/Jackalope)

Jackalope同样是@ifratric的作品，估计是对AFL/winafl不太满意，写了这个fuzzer(最开始是只支持Windows和macOS，后来也支持Linux和Android)。

pe-afl(https://github.com/wmliang/pe-afl)

peafl64(https://github.com/Sentinel-One/peafl64)

二进制静态插桩，使得AFL能够在windows系统上对闭源软件进行fuzz，分别支持x32和x64。

e9patch(https://github.com/GJDuck/e9patch)

二进制静态插桩，使得AFL能够fuzz x64的Linux ELF二进制文件。

retrowrite(https://github.com/HexHive/retrowrite)

二进制静态插桩，使得AFL能够fuzz x64和aarch64的Linux ELF二进制文件。

AFLplusplus(https://github.com/AFLplusplus/AFLplusplus)

AFL作者离开google无人维护之后社区维护的一个AFL版本。

AFLplusplus-cs(https://github.com/RICSecLab/AFLplusplus-cs/tree/retrage/cs-mode-support)

AFL++ CoreSight模式，该项目使用CoreSight(某些基于ARM的处理器上可用的CPU功能)向AFL++添加了新的反馈机制。

WAFL(https://github.com/fgsect/WAFL)

将AFL用于fuzz WebAssembly。

boofuzz(https://github.com/jtpereyda/boofuzz)

一个网络协议fuzz框架，前身是[sulley](https://github.com/OpenRCE/sulley)。

opcua_network_fuzzer(https://github.com/claroty/opcua_network_fuzzer)

基于boofuzz修改fuzz OPC UA协议，用于pwn2own 2022中。

syzkaller(https://github.com/google/syzkaller)

google开源的linux内核fuzz工具，也有将其移植到windows/macOS的资料。

GitLab's protocol fuzzing framework(https://gitlab.com/gitlab-org/security-products/protocol-fuzzer-ce)

peach是前几年比较流行的协议fuzz工具，分为免费版和收费版，在2020年gitlab收购了开发peach的公司之后于2021年进行了开源。不过从commit记录来看目前gitlab也没有怎么维护。

buzzer(https://github.com/google/buzzer)

google开源的eBPF fuzzer。

wtf(https://github.com/0vercl0k/wtf)

基于内存快照的fuzzer，可用于fuzz windows的用户态和内核态程序，很多人通过这个工具也是收获了CVE。类似于winafl这样的工具有两个大的痛点：1.需要对目标软件输入点构造harness，而这对于复杂的闭源软件往往会非常困难；2.有些软件只有先执行特定的函数，harness调用的输入点函数才能够正常运行，这个逻辑很多时候没法绕开。wtf通过对内存快照进行fuzz，不必编写harness，减少了分析成本。当然wtf也不是万能的，例如快照不具备IO访问能力，发生IO操作时wtf无法正确处理，需要用patch的方式修改逻辑(例如printf这种函数都是需要patch的)。

[基于快照的fuzz工具wtf的基础使用](https://paper.seebug.org/2084/)

TrapFuzz(https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz)

trapfuzzer(https://github.com/hac425xxx/trapfuzzer)

通过断点粗略实现统计代码覆盖率。

go-fuzz(https://github.com/dvyukov/go-fuzz)

jazzer(https://github.com/CodeIntelligenceTesting/jazzer)

jazzer.js(https://github.com/CodeIntelligenceTesting/jazzer.js)

fuzzers(https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers)

对不同编程语言的fuzz。

yarpgen(https://github.com/intel/yarpgen)

生成随机程序查找编译器错误。

cryptofuzz(https://github.com/guidovranken/cryptofuzz)

对一些密码学库的fuzz。

(google的另外两个密码学库测试工具：

https://github.com/google/wycheproof

https://github.com/google/paranoid_crypto)

mutiny-fuzzer(https://github.com/Cisco-Talos/mutiny-fuzzer)

思科的一款基于变异的网络fuzz框架，其主要原理是通过从数据包(如pcap文件)中解析协议请求并生成一个.fuzzer文件，然后基于该文件对请求进行变异，再发送给待测试的目标。

KernelFuzzer(https://github.com/FSecureLABS/KernelFuzzer)

windows内核fuzz。

domato(https://github.com/googleprojectzero/domato)

还是@ifratric的作品，根据语法生成代码，所以可以扩展用来fuzz各种脚本引擎。

fuzzilli(https://github.com/googleprojectzero/fuzzilli)

前project zero又一位大佬的js引擎fuzzer，该fuzzer效果太好，很多人拿着二次开发都发现了很多漏洞，后来他离开project zero在google专门搞V8安全了。

SMB_Fuzzer(https://github.com/mellowCS/SMB_Fuzzer)

SMB fuzzer。

libprotobuf-mutator(https://github.com/google/libprotobuf-mutator)

2016年google提出Structure-Aware Fuzzing，并基于libfuzzer与protobuf实现了libprotobuf-mutator，它弥补了peach的无覆盖引导的问题，也弥补了afl对于复杂输入类型的低效变异问题。Structure-Aware Fuzzing并不是什么新技术，跟Peach的实现思路是一样的，只是对输入数据类型作模板定义，以提高变异的准确率。

restler-fuzzer(https://github.com/microsoft/restler-fuzzer)

有些时候fuzz还会遇到状态的问题，特别是一些网络协议的fuzz，触发漏洞的路径可能很复杂，所以提出了Stateful Fuzzing的概念，通过程序运行中的状态机来指导fuzz，restler-fuzzer就是微软开发的第一个Stateful REST API Fuzzing工具。

## 其他辅助工具

BugId(https://github.com/SkyLined/BugId)

Windows系统上的漏洞分类和可利用性分析工具，编写Windows平台的fuzzer时通常会用到。

binspector(https://github.com/binspector/binspector)

二进制格式分析。

apicraft(https://github.com/occia/apicraft)

GraphFuzz(https://github.com/hgarrereyn/GraphFuzz)

自动化生成harness。

## blog

### general

一些关于fuzz的资源：

[https://fuzzing-project.org/](https://fuzzing-project.org/)

project zero成员@jooru的博客：

[https://j00ru.vexillium.org/](https://j00ru.vexillium.org/)

github securitylab有很多关于漏洞挖掘的文章：

[https://securitylab.github.com/research/](https://securitylab.github.com/research/)

### windows

微信：

[Fuzzing WeChat’s Wxam Parser](https://www.signal-labs.com/blog/fuzzing-wechats-wxam-parser)

RDP：

[Fuzzing RDPEGFX with "what the fuzz"](https://blog.thalium.re/posts/rdpegfx/)

[Fuzzing Microsoft's RDP Client using Virtual Channels: Overview & Methodology](https://thalium.github.io/blog/posts/fuzzing-microsoft-rdp-client-using-virtual-channels/)

PDF：

[Fuzzing Closed Source PDF Viewers](https://www.gosecure.net/blog/2019/07/30/fuzzing-closed-source-pdf-viewers/)

[50 CVEs in 50 Days: Fuzzing Adobe Reader](https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/)

[Creating a fuzzing harness for FoxitReader 9.7 ConvertToPDF Function](https://christopher-vella.com/2020/02/28/creating-a-fuzzing-harness-for-foxitreader-9-7-converttopdf-function/)

MSMQ：

[FortiGuard Labs Discovers Multiple Vulnerabilities in Microsoft Message Queuing Service](https://www.fortinet.com/blog/threat-research/microsoft-message-queuing-service-vulnerabilities)

windows图片解析：

[Fuzzing Image Parsing in Windows, Part One: Color Profiles](https://www.mandiant.com/resources/fuzzing-image-parsing-in-windows-color-profiles)

[Fuzzing Image Parsing in Windows, Part Two: Uninitialized Memory](https://www.mandiant.com/resources/fuzzing-image-parsing-in-windows-uninitialized-memory)

[Fuzzing Image Parsing in Windows, Part Three: RAW and HEIF](https://www.mandiant.com/resources/fuzzing-image-parsing-three)

[Fuzzing Image Parsing in Windows, Part Four: More HEIF](https://www.mandiant.com/resources/fuzzing-image-parsing-windows-part-four)

windows office：

[Fuzzing the Office Ecosystem](https://research.checkpoint.com/2021/fuzzing-the-office-ecosystem/)

POC2018，fuzz出了多个文件阅读器的漏洞，fuzzer原理类似前面说的trapfuzz

[Document parsers "research" as passive income](https://powerofcommunity.net/poc2018/jaanus.pdf)

HITB2021，也是受到前一个slide的启发，fuzz出了多个excel漏洞

[How I Found 16 Microsoft Office Excel Vulnerabilities in 6 Months](https://conference.hitb.org/hitbsecconf2021ams/materials/D2T1%20-%20How%20I%20Found%2016%20Microsoft%20Office%20Excel%20Vulnerabilities%20in%206%20Months%20-%20Quan%20Jin.pdf)

fuzz文件阅读器中的脚本引擎，fuzz出了多个foxit和adobe的漏洞，比domato先进的地方在于有一套算法去推断文本对象和脚本之间的关系

[https://github.com/TCA-ISCAS/Cooper](https://github.com/TCA-ISCAS/Cooper)

[COOPER: Testing the Binding Code of Scripting Languages with Cooperative Mutation](https://www.ndss-symposium.org/wp-content/uploads/2022-353-paper.pdf)

开发语法感知的fuzzer，发现解析postscript的漏洞

[Smash PostScript Interpreters Using A Syntax-Aware Fuzzer](https://www.zscaler.com/blogs/security-research/smash-postscript-interpreters-using-syntax-aware-fuzzer)

windows字体解析：

[A year of Windows kernel font fuzzing Part-1 the results](https://googleprojectzero.blogspot.com/2016/06/a-year-of-windows-kernel-font-fuzzing-1_27.html)

[A year of Windows kernel font fuzzing Part-2 the techniques](https://googleprojectzero.blogspot.com/2016/07/a-year-of-windows-kernel-font-fuzzing-2.html)

### linux/android

使用AFL fuzz linux内核文件系统：

[Filesystem Fuzzing with American Fuzzy lop](https://events.static.linuxfound.org/sites/events/files/slides/AFL%20filesystem%20fuzzing%2C%20Vault%202016_0.pdf)

条件竞争fuzz：

[KCSAN](https://github.com/google/kernel-sanitizers/blob/master/KCSAN.md)

[KTSAN](https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md)

[krace](https://github.com/sslab-gatech/krace)

[razzer](https://github.com/compsec-snu/razzer)

linux USB fuzz：

[https://github.com/purseclab/fuzzusb](https://github.com/purseclab/fuzzusb)

[FUZZUSB: Hybrid Stateful Fuzzing of USB Gadget Stacks](https://lifeasageek.github.io/papers/kyungtae-fuzzusb.pdf)

linux设备驱动fuzz：

[https://github.com/messlabnyu/DrifuzzProject/](https://github.com/messlabnyu/DrifuzzProject/)

[Drifuzz: Harvesting Bugs in Device Drivers from Golden Seeds](https://www.usenix.org/system/files/sec22-shen-zekun.pdf)

[https://github.com/secsysresearch/DRFuzz](https://github.com/secsysresearch/DRFuzz)

[Semantic-Informed Driver Fuzzing Without Both the Hardware Devices and the Emulators](https://www.ndss-symposium.org/wp-content/uploads/2022-345-paper.pdf)

使用honggfuzz fuzz VLC：

[Double-Free RCE in VLC. A honggfuzz how-to](https://www.pentestpartners.com/security-blog/double-free-rce-in-vlc-a-honggfuzz-how-to/)

使用AFL++的frida模式fuzz apk的so库，讨论了三种情况：无JNI、有JNI(不和apk字节码交互)、有JNI(和apk字节码交互)：

[Android greybox fuzzing with AFL++ Frida mode](https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html)

fuzz android系统服务：

[The Fuzzing Guide to the Galaxy: An Attempt with Android System Services](https://blog.thalium.re/posts/fuzzing-samsung-system-services/)

### macOS

我专门整理的macOS的漏洞挖掘资料在这里：

[https://github.com/houjingyi233/macOS-iOS-system-security](https://github.com/houjingyi233/macOS-iOS-system-security)

### DBMS

关于DBMS的漏洞挖掘资料可以参考这里：

[https://github.com/zhangysh1995/awesome-database-testing](https://github.com/zhangysh1995/awesome-database-testing)

### VM

关于VMware的漏洞挖掘资料可以参考这里：

[https://github.com/xairy/vmware-exploitation](https://github.com/xairy/vmware-exploitation)

一些其他的：

[Hunting for bugs in VirtualBox (First Take)](http://blog.paulch.ru/2020-07-26-hunting-for-bugs-in-virtualbox-first-take.html)

### IOT

对固件镜像进行自动化fuzz：

fuzzware(https://github.com/fuzzware-fuzzer/fuzzware/)

将嵌入式固件作为Linux用户空间进程运行从而fuzz：

SAFIREFUZZ(https://github.com/pr0me/SAFIREFUZZ)

### browser

Mozilla是如何fuzz浏览器的：

[Browser fuzzing at Mozilla](https://blog.mozilla.org/attack-and-defense/2021/05/20/browser-fuzzing-at-mozilla/)

通过差分模糊测试来检测错误的JIT优化引起的不一致性：

[https://github.com/RUB-SysSec/JIT-Picker](https://github.com/RUB-SysSec/JIT-Picker)

[Jit-Picking: Differential Fuzzing of JavaScript Engines](https://publications.cispa.saarland/3773/1/2022-CCS-JIT-Fuzzing.pdf)

将JS种子分裂成代码块，每个代码块有一组约束，表示代码块什么时候可以和其他代码块组合，生成在语义和语法上正确的JS代码：

[https://github.com/SoftSec-KAIST/CodeAlchemist](https://github.com/SoftSec-KAIST/CodeAlchemist)

[CodeAlchemist: Semantics-Aware Code Generation to Find Vulnerabilities in JavaScript Engines](https://cseweb.ucsd.edu/~dstefan/cse291-spring21/papers/han:codealchemist.pdf)

### bluetooth

这人发现了很多厂商的蓝牙漏洞，braktooth是一批传统蓝牙的漏洞，sweyntooth是一批BLE的漏洞。fuzzer没有开源是提供的二进制，不过可以参考一下：

[https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks)

[https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks)

BLE fuzz：

[Stateful Black-Box Fuzzing of BLE Devices Using Automata Learning](https://git.ist.tugraz.at/apferscher/ble-fuzzing/)

### WIFI

fuzz出了mtk/华为等厂商路由器wifi协议的多个漏洞：

[https://github.com/efchatz/WPAxFuzz](https://github.com/efchatz/WPAxFuzz)

蚂蚁金服的wifi协议fuzz工具，基于openwifi，也fuzz出了多个漏洞：

[https://github.com/alipay/Owfuzz](https://github.com/alipay/Owfuzz)
