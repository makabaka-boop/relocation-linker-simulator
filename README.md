# jsonlink

`jsonlink` 是一个只读取 JSON 对象描述、不解析 ELF 的 Go 命令行链接器。

## 输入

顶层输入可以是：

- 单个对象；
- 对象数组；
- 或 `{"objects":[...]}`。

`bytes` 可用 base64 字符串，也可用 0–255 的 JSON 数字数组。

```json
{
  "name": "example.o",
  "text": {"bytes": "AA==", "align": 4},
  "data": {"bytes": [1, 0, 0, 0], "align": 1},
  "symbols": [
    {"name": "local_x", "section": ".text", "offset": 0, "scope": "local"},
    {"name": "global_x", "section": ".text", "offset": 0, "scope": "global", "binding": "strong"}
  ],
  "relocations": [
    {"type": "ABS32", "section": ".data", "offset": 0, "symbol": "global_x", "addend": 0}
  ]
}
```

字段说明：

- `align`：只能是 `1`、`2`、`4`、`8`、`16`；省略时为 `1`。
- `scope`：`local` 或 `global`；省略时为 `global`。
- `binding`：全局符号为 `strong` 或 `weak`；省略时为 `strong`。局部符号没有绑定。
- `type`：
  - `ABS32`：写入 `target + addend`，占 4 字节，无符号范围 `0..0xffffffff`。
  - `PCREL16`：写入 `target + addend - patch_end`，占 2 字节，有符号范围 `-32768..32767`。
- 所有多字节写入均为小端序。
- `addend` 可省略，省略值为 0。

## 布局规则

- 映像基址固定为 `0x1000`。
- 先放置全部 `.text`，再放置全部 `.data`。
- 同一段内严格按输入对象顺序放置。
- 每个对象段起始地址满足自身对齐；对齐间隙填 0。

## 符号与错误

- 局部符号只在所属对象内可见；不同对象可同名。
- 全局强定义优先于弱定义。
- 两个强全局符号同名会报错。
- 仅有弱定义且同名时，保留第一个弱定义。
- 重定位引用不到符号会报错。
- 补丁超出段、`ABS32` 或 `PCREL16` 值越界都会报错。
- 链接成功前不会写映像或报告；`-o` 输出通过临时文件加原子替换完成，失败不会替换已有文件。

## 用法

从标准输入读取 JSON，并将完整 JSON 报告打印到标准输出：

```sh
jsonlink < objects.json
```

写二进制映像和报告：

```sh
jsonlink -o image.bin -report report.json objects.json
```

报告包含：

- base64 编码的完整映像；
- 每个已放置对象段的地址、大小、对齐和最终字节；
- 每个符号的地址，以及弱定义是否被选中；
- 每条重定位的补丁起止地址、解析到的定义对象、目标地址、加数、计算值和补丁前后字节。

## 测试

```sh
go test ./...
go vet ./...
```

测试中的主示例是手工计算的小对象，覆盖：

- 1/2/4/8/16 字节对齐；
- 局部符号作用域隔离；
- 强/弱全局符号选择；
- 小端 `ABS32` 和有符号小端 `PCREL16`；
- `PCREL16` 正负边界和越界；
- 未解析符号、重复强符号、越界补丁；
- 链接失败时不产生或替换输出文件。
