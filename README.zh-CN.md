# Mac File Gateway 2.3.0

2.3.0 在 2.2.0 的读写、目录创建、删除、移动/重命名能力上增加了**受控命令执行**，用于真实运行 `go test`、`go vet`、Python 编译检查和 pytest。

## 启动示例

```bash
bash setup.sh

bash run.sh "/absolute/path/to/project" \
  --allow-write \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-a \
  --exec-runner service-c=pipenv
```

执行权限和写权限相互独立；`--allow-exec` 必须至少配置一个 `--exec-path`。

## service-c / Pipenv

对：

```text
cwd="service-c"
argv=["pytest", "-q"]
```

若显式配置：

```bash
--exec-runner service-c=pipenv
```

实际执行为：

```text
cwd = <root>/service-c
argv = ["pipenv", "run", "pytest", "-q"]
```

因此不需要保持一个交互式 `pipenv shell`。如果未显式配置 runner，网关只会在当前允许的 exec scope 内向上寻找 `Pipfile`；找到则自动使用 `pipenv run`，否则 direct。

## run_command

MCP 工具：

```text
run_command(
  cwd,
  argv,
  timeout_seconds=60,
  dry_run=true
)
```

HTTP 对应 `POST /run`。

允许的命令形态：

- `pytest ...`
- `python -m pytest ...`
- `python -m compileall ...`
- `python relative_script.py ...`
- `go test ...`
- `go vet ...`

明确禁止：

- 任意 shell / `sh -c` / `bash -lc`
- pipe、redirect、command substitution 等 shell 语义
- `python -c`、stdin Python
- `git`、`curl`、`rm` 等任意其他 executable
- 显式指向项目外的绝对路径或 `..` 参数
- Go 的 `-exec` / `-toolexec` / `-vettool`

默认 `dry_run=true`，只返回最终 runner 和 argv；`dry_run=false` 才实际运行。stdin 关闭，超时范围 1-300 秒，stdout/stderr 有容量限制并做 best-effort credential redaction，常见 secret 环境变量和 `VIRTUAL_ENV` 不继承。

## 重要安全边界

这**不是 macOS 沙箱**。只要执行 `pytest`、Go test 或 Python 脚本，项目代码本身就以“启动网关的 macOS 用户”权限运行；代码仍可能访问项目外文件或网络。exec scope 控制的是“从哪里、以什么命令形态启动”，不是限制被运行代码的系统权限。

因此只应对可信项目开启，并尽量缩小：

```bash
--exec-path service-c --exec-path service-a
```

完整策略见 `docs/CONTROLLED_EXEC.md`。
