import Foundation

// MARK: - Bundled Reverse-Engineering Skills
//
// [zzuu-re] zzuu ships as an AI mobile-RE workstation. These skills are
// embedded the same way skill-creator is (Swift string constant, imported at
// first launch, auto-synced to both the app-side skills dir and the iSH
// rootfs so the model can read them from either side). They teach the agent
// the layered workflow this build enables:
//
//   re-ios-triage      — sandbox static layer (unzip / rabin2 / strings)
//   re-frida-dynamic   — host dynamic layer via root_execute (frida-server)
//   re-objc-api        — class-dump + dylib symbol triage
//   re-anti-detect     — jailbreak/SSL-pinning/instrumentation bypass notes
//   re-theos-tweak     — Theos Tweak.xm → .deb build on server → install
final class BundledRESkills {

    static let version = "1.0.0"

    // MARK: re-ios-triage

    static let iosTriage = """
---
name: re-ios-triage
version: \(BundledRESkills.version)
description: iOS App 逆向第一步:IPA 解包、Mach-O 结构分析、字符串/符号提取、加密检测。用户给出 IPA 文件路径或 App 名称时触发。
---

# iOS App 静态分析(Triage)

目标:拿到一个 iOS App(IPA 或已安装 App),建立它的结构认知。全程在 Linux 沙箱(shell_execute)完成;需要真机上的东西时用 root_execute。

## 0. 工具自举(首次使用执行一次)

```sh
apk add --no-cache radare2 binwalk yara python3 py3-pip >/dev/null 2>&1 || true
which rabin2 || apk add --no-cache radare2
```

radare2 提供 rabin2/rasm2/rafind2 等全套静态工具,Alpine 直接可装。

## 1. 获取二进制

三种来源,按优先级:

**A. 用户给了 IPA 文件**(在 /var/minis/attachments 或 workspace):
```sh
mkdir -p /var/minis/workspace/re/<appname> && cd /var/minis/workspace/re/<appname>
unzip -o <path>.ipa -d ipa >/dev/null
ls ipa/Payload/*.app            # 找到 .app
BIN=ipa/Payload/<App>.app/<AppMainExecutable>   # 名字看 Info.plist 的 CFBundleExecutable
```

**B. 从越狱真机拉解密后的主程序**(最常用,root_execute):
iOS 上磁盘里的主程序是 FairPlay 加密的,必须走 frida 脱密 → 见 re-frida-dynamic 技能第 2 节。
未加密的部分(dylib 通常不加密)可以直接拷:
```
root_execute: find /private/var/containers/Bundle/Application -maxdepth 3 -name "*.app" 2>/dev/null | grep -i <关键词>
root_execute: cp <bundle路径>/<dylib名> /var/mobile/
```
然后从沙箱侧取回(见第 5 节文件搬运)。

**C. 只分析单个 dylib/framework**:直接拿文件进第 2 节。

## 2. Mach-O 结构速览

```sh
file $BIN                                        # fat/thin、架构
rabin2 -I $BIN                                   # info:入口点、编译信息
rabin2 -l $BIN                                   # load commands
rabin2 -L $BIN 2>/dev/null | head -40            # 依赖的动态库
```

加密检测(判断主程序是否 FairPlay 加密):
```sh
rabin2 -I $BIN | grep -i crypt
# LC_ENCRYPTION_INFO 且 cryptsize > 0 → 加密,需 frida 脱密
```

## 3. 符号与字符串

```sh
rabin2 -s $BIN | head -60                        # 符号表
rabin2 -S $BIN | head -40                        # section
strings -n 8 $BIN | grep -iE "http|api|token|key|sign|secret" | head -50   # 接口线索
strings -n 8 $BIN | grep -E "^/v[0-9]|^https?://" | sort -u | head -40     # URL
```

ObjC 类清单(判断业务逻辑位置):
```sh
strings $BIN | grep -F "_OBJC_CLASS" | sed 's/^_OBJC_CLASS//' | sort -u | head -80
```

## 4. 关键配置文件

```sh
plutil -convert xml1 -o - ipa/Payload/<App>.app/Info.plist 2>/dev/null || cat ipa/Payload/<App>.app/Info.plist
# 关注:CFBundleURLTypes(深链)、NSAppTransportSecurity(ATS 豁免域名!)、UIBackgroundModes
plutil -p ipa/Payload/<App>.app/_CodeSignature/CodeResources 2>/dev/null | grep -i entitle | head
```

**ATS 豁免域名是金矿**:被豁免的域名说明 App 跟它有明文 HTTP 通信,抓包必中。

## 5. 真机 ↔ 沙箱文件搬运

关键事实:**iSH 没有网络隔离**——沙箱里监听的端口在真机 127.0.0.1 上直接可达。
所以大文件走本地回环传输,秒级完成:

**沙箱 → 真机**(HTTP 方式,最稳):
```sh
# 沙箱:起临时 HTTP 服务(后台)
cd /var/minis/workspace/re && python3 -m http.server 8765 >/dev/null 2>&1 &
# 真机:拉取
root_execute: curl -sf -o /var/mobile/<name>.bin http://127.0.0.1:8765/<相对路径>
# 用完杀掉
pkill -f "http.server 8765" 2>/dev/null
```

**真机 → 沙箱**(nc 落盘方式,iOS 无 python):
```
root_execute: (nc -l 9999 > /var/mobile/incoming.bin 2>/dev/null &) ; sleep 0.3
# 沙箱:推
curl -sf --data-binary @/var/minis/workspace/re/x.bin http://127.0.0.1:9999
root_execute: ls -la /var/mobile/incoming.bin
```

**小文件(<20KB)** 直接 base64 一行搞定:
```
root_execute: base64 /var/mobile/small.txt     # 输出拿回沙箱 base64 -d
```
**兜底**:用户挂载过共享文件夹时,/var/minis/mounts/<name> 两侧可见,直接 cp。

## 6. 产出格式

triage 完成后给用户一份简报:
- 架构/加密状态/签名团队 ID
- 主要业务 dylib 列表(哪些值得深入)
- 发现的 API 域名清单(标出 ATS 豁免的)
- 建议的下一步(动态 hook 哪些类/函数)
"""

    // MARK: re-frida-dynamic

    static let fridaDynamic = """
---
name: re-frida-dynamic
version: \(BundledRESkills.version)
description: 越狱真机上的 Frida 动态分析:frida-server 管理、进程 attach/spawn、内存脱密 dump、运行时 hook。需要 root_execute 可用。
---

# Frida 动态分析(越狱真机)

所有宿主操作通过 root_execute 执行;iSH 沙箱侧跑 frida-tools 客户端(pip 安装)。

## 0. 工具自举

沙箱侧(客户端):
```sh
pip3 install frida-tools 2>/dev/null || pip3 install frida-tools --user
```
注意:沙箱是 **aarch64 musl Linux**,frida 的 wheel 可能不兼容。如果 pip 装的 frida 起不来,
备选方案:全部用 root_execute 在真机上跑 frida 命令(真机 frida 工具链完整,最稳)。

真机侧(服务端,root_execute):
```
root_execute: which frida-server || echo MISSING
```
没有 frida-server 时:让用户从 GitHub frida/releases 下载对应 iOS 版本放进设备
(如 /var/jb/usr/bin/frida-server),或 Sileo 装。版本必须和客户端一致。

启动:
```
root_execute: pkill frida-server 2>/dev/null; nohup /var/jb/usr/bin/frida-server -l 0.0.0.0:27042 >/tmp/frida.log 2>&1 & sleep 1; pgrep frida-server
```

## 1. 进程侦察

```
root_execute: ps aux | grep -i <app关键词>          # 找进程名
root_execute: lsappinfo list 2>/dev/null | grep -B2 -i <关键词>   # bundle id
```

## 2. 内存脱密 dump(核心能力)

FairPlay 加密的主程序在运行态内存里是明文的。标准流程:
```
# 1) 确保 frida-ios-dump 就位(推荐直接复用 AloneMonkey/frida-ios-dump,GitHub 3.9k★)
root_execute: [ -x /var/jb/usr/bin/frida-ios-dump ] || { curl -fsSL https://raw.githubusercontent.com/AloneMonkey/frida-ios-dump/master/frida-ios-dump -o /var/jb/usr/bin/frida-ios-dump && chmod +x /var/jb/usr/bin/frida-ios-dump; }
# 2) dump(参数是 bundle id 或进程名)
root_execute: /var/jb/usr/bin/frida-ios-dump -o /var/mobile/<App>_decrypted.bin <bundle_id>
```
原理:spawn App → 注入脚本读取 __TEXT 段全部页(此时 FairPlay 已解密)→ 写出 Mach-O。
产物在真机 /var/mobile/,按 re-ios-triage 第 5 节搬回沙箱分析。

## 3. Hook 与调用追踪

通用套路(把 JS 写到真机 /tmp/hook.js 再注入):
```
root_execute: cat > /tmp/hook.js <<'JSEOF'
// 例:hook NSURLSession 请求
Interceptor.attach(ObjC.classes.NSURLSession.dataTaskWithRequest_completionHandler_.implementation, {
  onEnter: function(a) { console.log("REQ: " + new ObjC.Object(a[1]).absoluteString()); }
});
JSEOF
root_execute: /var/jb/usr/bin/frida -n <App> -l /tmp/hook.js --no-pause 2>&1 | tee /tmp/hook.log
```
常用 hook 点:
- `NSURLSession dataTaskWithRequest:` — 全量 HTTP 请求+参数
- `SecTrustEvaluateWithError` — 证书校验(返回 true 即拆 SSL pinning)
- 签名函数(class-dump 找出来的 sign/hash 方法)— 打印入参出参
- `-[UIWindow becomeKeyWindow]` — 启动时机
- 任意 ObjC 方法 — %hook 风格用 Theos,JS 风格用 Interceptor

结果回收:`root_execute: tail -n 200 /tmp/hook.log`(长任务轮询)。

## 4. 反调试/反 frida 应对

- frida-server 改名: `mv frida-server fs; ./fs`(特征扫描的是名字)
- 端口换掉: `-l 127.0.0.1:31337`
- 进程保护:很多 App 扫 /proc/self/maps 找 frida 特征串 → 用 suifei/fridare 重打包 frida-server 改特征(GitHub 938★)
- 仍被杀:先 class-dump 静态摸清,再用 gadget 注入替代 spawn 方式(见 re-anti-detect)

## 5. 纪律

- 每次 root_execute 前先 `pgrep frida-server` 确认存活,死了先拉起
- hook 日志一律落盘 /tmp/*.log 再 tail,不要指望一次性拿全
- 脱密产物命名规范:/var/minis/workspace/re/<app>/<app>_decrypted_<date>.bin
"""

    // MARK: re-objc-api

    static let objcApi = """
---
name: re-objc-api
version: \(BundledRESkills.version)
description: ObjC API 提取与分析:class-dump 头文件生成、私有框架 API 梳理、dylib 职责划分。分析 iOS App 的类结构和调用关系时使用。
---

# ObjC API 提取(class-dump)

ObjC 的元数据在二进制的 __objc_* 段里是明文,可以完整还原类/协议/方法签名——这是 iOS 逆向相对 Android 的最大优势。

## 0. 工具自举

class-dump 不在 Alpine 仓库,源码编译(沙箱内,约 1 分钟):
```sh
apk add --no-cache clang make git >/dev/null 2>&1 || true
[ -x /usr/local/bin/class-dump ] || {
  rm -rf /tmp/cd && git clone --depth 1 https://github.com/DreamDevLost/classdumpios /tmp/cd
  cd /tmp/cd && (make -j4 2>/dev/null || cc src/class-dump.c -o /usr/local/bin/class-dump 2>/dev/null)
}
which class-dump || echo "BUILD_FAILED — fallback to rabin2 symbols"
```
编译失败时的降级方案(rabin2 提符号,精度低但够用):
```sh
rabin2 -s <binary> | grep -E "OBJC" | head -100
```

## 1. 生成头文件

```sh
cd /var/minis/workspace/re/<app>
class-dump -H <decrypted_binary_or_dylib> -o headers/
# 单文件版: class-dump <binary> > api.h
wc -l headers/*.h    # 规模感知:几万行很正常
```

## 2. 快速定位业务代码

```sh
# App 自己的类 vs 三方 SDK:按前缀聚类
grep -h "^@interface" headers/*.h | awk '{print $2}' | cut -d' ' -f1 | sed 's/\\..*//' | cut -c1-4 | sort | uniq -c | sort -rn | head -20
# 常见前缀含义:AF*=AFNetworking, SD*=SDWebImage, WX*=微信SDK,
# UTDID/UT*=阿里埋点, Bugly*=腾讯崩溃, FIR*/GTM*=Firebase
```

## 3. 挖签名/加密逻辑

```sh
# 找 sign/token/crypto 相关方法
grep -riE "\\(.*(sign|encrypt|decrypt|hash|hmac|md5|sha|aes|rsa).*\\)" headers/*.h | head -40
# 找网络层
grep -rl "request\\|Request" headers/*.h | xargs grep -l "dataTask\\|URLSession" 2>/dev/null | head
```

## 4. 交叉验证

class-dump 只有声明没有实现。确认某个方法是签名的:
1. 静态:`strings` 找它附近的常量(key/salt/算法名)
2. 动态:re-frida-dynamic hook 该方法,打印入参出参对比
3. 反汇编:`r2 -A <binary>` 后 `pdf @ <method地址>`(rabin2 -j 拿地址)

## 5. 产出

- headers/ 目录保留在 workspace(后续会话可复用)
- 给用户:Top 业务类清单 + 疑似签名/加密方法列表 + 三方 SDK 识别表
"""

    // MARK: re-anti-detect

    static let antiDetect = """
---
name: re-anti-detect
version: \(BundledRESkills.version)
description: iOS App 反检测绕过手册:越狱检测、Frida 检测、SSL Pinning、完整性校验。动态分析被 App 识破/杀掉时查这个。
---

# 反检测绕过(iOS)

动态分析时 App 闪退、拒绝启动、功能异常,大概率命中了检测。按下面顺序排查。

## 1. 症状 → 原因对照

| 症状 | 最可能原因 | 对策 |
|---|---|---|
| spawn 后立即退出 | frida 特征扫描 | 第 2 节 |
| 能启动但网络全挂 | SSL Pinning | 第 3 节 |
| 特定功能报"环境异常" | 越狱检测 | 第 4 节 |
| 间歇性崩溃 | 完整性校验/时间戳 | 第 5 节 |

## 2. Frida 检测绕过

检测手段(按出现频率):
1. **maps 扫描**:遍历 /proc/self/maps 找 "frida"/"gum-js-log" 等串
2. **端口探测**:连 27042
3. **线程名**:frida 线程名特征
4. **ptrace 检测**:fork+wait 看 PTRACE_TRACEME 返回值

绕过:
```
# 最小改动:改名+换端口(解决一半 maps 扫描和端口探测)
root_execute: mv /var/jb/usr/bin/frida-server /var/jb/usr/bin/fs && /var/jb/usr/bin/fs -l 127.0.0.1:31337 &
# 深度:重打包改特征串
root_execute: [ -d /var/mobile/fridare ] || git clone --depth 1 https://github.com/suifei/fridare /var/mobile/fridare
# 终极:gadget 注入(无 server 进程,零端口)——把 libgadget.dylib 塞进 App bundle 重签
```
gadget 路线(重签装机,TrollStore 支持):
1. 拿 libgadget.dylib(frida releases,iOS os 版)
2. 塞进 Payload/App.app/ 根目录
3. 用 fakesigner/monkeySign 重签(需要先有一个能跑的注入点,鸡生蛋问题 → 先用 frida-server 跑通一次)

## 3. SSL Pinning 拆除

三档,从轻到重:
```js
// 档1:hook 信任评估(最常用)
var orig = Module.findExportByName(null, "SecTrustEvaluateWithError");
Interceptor.replace(orig, new NativeFunction(() => true, 'bool', ['pointer','pointer']));

// 档2:NSURLSession 委托
// hook -[delegate URLSession:didReceiveChallenge:completionHandler:] 直接放行

// 档3:swizzle 自定义 pinning 类(class-dump 找出来,常见名:*CertificatePinner*, *SSLValidator*)
```
配合抓包:沙箱内 mitmproxy(`pip3 install mitmproxy`)监听 8080,真机代理指向手机 IP。
**前提**:ATS 豁免(见 re-ios-triage 第 4 节)或上面拆了 pinning,否则 HTTPS 全失败。

## 4. 越狱检测绕过

检测点:cydia/substitute 路径存在性、/var/jb 可写、SSH 端口、root 进程、SpringBoard 私有 API。
方案:
- **越狱隐藏 tweak**:Relaxin/Sileo 里装 JB 隐藏类 tweak(搜 hidejailbreak / JBHide 同类)
- **hook 系统调用**:拦截 stat/access/open 对敏感路径的查询,返回不存在
- 注意:OpenSSH 开着本身就是强越狱信号,分析完记得 `launchctl stop sshd`

## 5. 完整性/其他

- 时间/时区检测:hook `time()`/`gettimeofday` 固定返回值
- 模拟器检测:真机不受影响,忽略
- 风控服务器端(设备指纹上报):只能观察不能本地绕;记录它上报的字段就是成果

## 纪律

- 每试一个绕过手段,先记下来(哪个有效),写进当天 memory
- 不要同时改多个变量,定位要单一变量
- 绕过成功 ≠ 分析结束:继续回到 re-frida-dynamic 的正常流程
"""

    // MARK: re-theos-tweak

    static let theosTweak = """
---
name: re-theos-tweak
version: \(BundledRESkills.version)
description: Theos Tweak 开发闭环:在沙箱写 Tweak.xm/control,推送到构建服务器编译 .deb,拉回越狱真机 dpkg 安装。需要 root_execute + 已配置 Theos 服务器。
---

# Theos Tweak 构建与安装

把逆向成果变成可安装的 tweak。分工:代码在沙箱写,编译在服务器(Theos 工具链),安装走 root_execute。

## 0. 前置:构建通道

编译在 **GitHub Actions 的 macOS runner** 上跑(Theos + Xcode sysroot,免费额度足够个人使用),
沙箱里用现成 CLI `minis-re-build` 一键触发:打包源码 → 派发 workflow → 轮询 → 下载 .deb。

环境变量(Settings > Environment Variables 配置后自动注入沙箱):
- `RE_BUILD_TOKEN`:GitHub PAT(repo + workflow 权限)
- `RE_BUILD_REPO`:hosting 仓库(默认 CN00K/zzuu)

验证:`which minis-re-build && echo $RE_BUILD_TOKEN | head -c 8`
缺 token 时提示用户去 Settings > Environment Variables 添加。

## 1. 项目骨架(沙箱内生成)

```sh
PROJ=/var/minis/workspace/re/<tweakname>
mkdir -p $PROJ/Source
cat > $PROJ/control <<EOF
Package: com.zzuu.<tweakname>
Name: <TweakName>
Version: 1.0.0
Architecture: iphoneos-arm64
Description: <一句话>
Author: zzuu
EOF
cat > $PROJ/Makefile <<'EOF'
include $(THEOS_MAKE_PATH)/makefiles/common

TWEAK_NAME = <TweakName>
<TweakName>_FILES = Source/Tweak.xm
<TweakName>_FRAMEWORKS = Foundation UIKit
ARCHS = arm64
TARGET = iphone:clang:latest:14.0
EOF
echo "骨架就绪: $PROJ"
```

## 2. 写 Tweak.xm(核心)

模板(按分析结果填 hook 点):
```objc
//%build -f objc-arc
#import <Foundation/Foundation.h>

%hook <TargetClass>
- (void)<targetMethod>:(id)arg {
    // 你的逻辑:观察 / 修改参数 / 短路返回
    %orig(arg);   // 调原方法(可选)
}
%end
```
常用模式:
- **观察**:NSLog 打印参数 → 装机后看日志确认行为
- **改参**:替换 arg 再 %orig
- **短路**:不调 %orig,直接 return 自定义值(拆校验/去广告常见)
- **注入 UI**:%constructor 里 dispatch_async main 加按钮

## 3. 一键编译(GitHub Actions)

```sh
minis-re-build /var/minis/workspace/re/<tweakname> /var/minis/workspace/re/<tweakname>.deb
```
内部流程:tar+base64 → POST workflow_dispatch(build-tweak.yml)→ 轮询 run 状态 → 下载 artifact。
全程 2-5 分钟,期间命令会阻塞等待,正常。

编译报错处理:失败时日志 zip 落在 /tmp/rebuild_logs.zip,解压读 build.log,常见错:
- 找不到头文件 → FRAMEWORKS 漏了
- 符号 undefined → 方法签名写错(class-dump 核对)
- 架构错 → ARCHS 必须是 arm64

## 4. 安装到真机

minis-re-build 成功后 .deb 已在沙箱。走回环 HTTP 传到真机再装(见 re-ios-triage 第 5 节):
```sh
# 沙箱:起临时服务
cd /var/minis/workspace/re && python3 -m http.server 8765 >/dev/null 2>&1 &
# 真机:下载并安装
root_execute: curl -sf -o /var/mobile/t.deb http://127.0.0.1:8765/<tweakname>.deb && dpkg -i /var/mobile/t.deb
# 沙箱:收工
pkill -f "http.server 8765" 2>/dev/null
root_execute: killall -9 <目标App进程名> 2>/dev/null   # 重启 App 生效
```

## 5. 验证与迭代

- 装机后让用户操作触发点,`root_execute: log stream --level debug --predicate 'process == "<App>"' 2>&1 | head -50` 看 NSLog
- 不生效:确认 %hook 类名拼写、App 是否重启、dylib 是否加载
- 卸载:`root_execute: dpkg -r com.zzuu.<tweakname>`

## 纪律

- 每个 tweak 独立目录,版本号递增
- control 的 Package 名唯一,避免和已有包冲突
- 编译产物 .deb 留档在 workspace,方便重装/分发
"""
}
