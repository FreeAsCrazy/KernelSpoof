# 需要AI Agent适配，使用此代码视为手机自杀，一切责任自己承担，直接叫AI Agent分析代码并说明如何适配，如何使用

## KernelSpoof
### 作用
> KernelPatch KPM，直接修改 `init_uts_ns` 伪装 `uname` 的 release/version，俗称 **内核伪装** 用于对抗内核检测，APatch里加载.kpm→运行正常后→嵌入boot.img
---

- 加载后会自动伪装
*Linux localhost 4.19.157-perf-g8779875ad741 #1 SMP PREEMPT Thu Mar 16 22:52:44 CST 2023 aarch64*，使用`rest`命令恢复真实值
- 控制方式有两种
>1. APatch内直接输入控制命令
>2. /proc/KernelSpoof提供给shell控制

### 命令

```text
status   显示状态和 release/version
set      自定义伪装，参数为完整 uname -a 输出
preset   预设伪装
rest     恢复真实值
help     显示帮助
```
- 只有 `set` 命令后需要跟数值
#### APatch内直接输入控制命令过于简单，只说/proc/KernelSpoof控制方式例子
```sh
# 查看状态
su -c 'echo status > /proc/KernelSpoof; cat /proc/KernelSpoof'
# 自定义伪装
su -c 'echo "set " > /proc/KernelSpoof'
# 应用预设
su -c 'echo preset > /proc/KernelSpoof'
# 恢复真实值
su -c 'echo rest > /proc/KernelSpoof'
# 查看帮助
su -c 'echo help > /proc/KernelSpoof; cat /proc/KernelSpoof'
```

## 构建
termux里执行termux-build.sh，自动生成KernelSpoof_0.1.kpm

## 工作流构建
1. 登录 → `Fork` → `Actions` →`Build KPM`→ `Run workflow` →`Run workflow`→ 在页面底部下载 `KernelSpoof-kpm`
2. 解压下载的 zip，得到 `KernelSpoof_0.1.kpm`

> [!NOTE]
> 本人有文件洁癖，此KernelSpoof拉的屎只有/proc/KernelSpoof，正常卸载会自动删除