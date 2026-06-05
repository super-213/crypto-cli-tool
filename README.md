# Crypto CLI Tool
使用kiro开发的
一个专业级的命令行加密工具，支持多种加密算法，用于加密和解密文件及目录。

## 目录

- [功能特性](#功能特性)
- [项目结构](#项目结构)
- [安装](#安装)
- [快速开始](#快速开始)
- [使用方法](#使用方法)
- [支持的算法](#支持的算法)
- [示例](#示例)
- [安全注意事项](#安全注意事项)
- [项目管理](#项目管理)

## 功能特性

- ✅ **多种加密算法**：支持 AES-256-GCM、ChaCha20-Poly1305、AES-256-CBC、RSA-OAEP、ECIES
- ✅ **对称和非对称加密**：灵活选择加密方式
- ✅ **密钥派生**：支持 Argon2id 和 PBKDF2-SHA256
- ✅ **文件和目录加密**：可加密单个文件或整个目录结构
- ✅ **流式处理**：高效处理大文件，内存占用恒定
- ✅ **压缩支持**：可选的 Gzip 或 Zstd 压缩
- ✅ **认证加密**：使用 AEAD 模式防止篡改
- ✅ **安全内存管理**：敏感数据在内存中自动清零
- ✅ **多种密钥输入方式**：密码、环境变量、密钥文件
- ✅ **交互式向导**：通过 `crypto -w` 按步骤选择语言、文件、操作、算法、密码和保存路径


## 项目结构

```
crypto-cli-tool/
├── src/
│   ├── main.rs              # 程序入口
│   ├── lib.rs               # 库入口
│   ├── cli.rs               # 命令行接口和参数解析
│   ├── app.rs               # 应用程序协调器
│   ├── crypto.rs            # 加密引擎核心
│   ├── key_manager.rs       # 密钥管理和派生
│   ├── file_handler.rs      # 文件处理和加密文件格式
│   ├── file_handler_impl.rs # 文件处理实现
│   ├── compression.rs       # 压缩引擎
│   ├── archive.rs           # 目录归档格式
│   ├── directory.rs         # 目录遍历
│   └── error.rs             # 错误类型定义
├── tests/
│   ├── crypto_test.rs       # 加密功能测试
│   ├── key_manager_test.rs  # 密钥管理测试
│   ├── file_handler_test.rs # 文件处理测试
│   ├── streaming_test.rs    # 流式加密测试
│   └── archive_test.rs      # 归档功能测试
├── .kiro/specs/             # 项目规范文档
│   └── crypto-cli-tool/
│       ├── requirements.md  # 需求文档
│       ├── design.md        # 设计文档
│       └── tasks.md         # 任务列表
├── Cargo.toml               # Rust 项目配置
├── proptest.toml            # 属性测试配置
└── README.md                # 本文件
```

### 核心模块说明

- **CLI Layer (cli.rs)**: 处理命令行参数解析、用户交互、进度显示
- **Application Layer (app.rs)**: 协调各模块，实现高层工作流
- **Encryption Engine (crypto.rs)**: 核心加密/解密操作
- **Key Manager (key_manager.rs)**: 密钥生成、派生、安全存储
- **File Handler (file_handler.rs)**: 文件 I/O、流式处理、加密文件格式
- **Compression Engine (compression.rs)**: 压缩/解压缩功能
- **Archive (archive.rs)**: 目录归档和提取


## 安装

### 前置要求

- Rust 1.70 或更高版本
- Cargo（Rust 包管理器）

### 从源码构建

```bash
# 克隆仓库
git clone <repository-url>
cd crypto-cli-tool

# 构建项目
cargo build --release

# 二进制文件位于
./target/release/crypto-cli-tool
```

### 安装到系统

```bash
# 安装到 ~/.cargo/bin/
cargo install --path .

# 现在可以直接使用
crypto-cli-tool --help
```

## 快速开始

### 交互式向导（普通用户推荐）

```bash
# 启动交互式加密/解密向导
crypto -w

# 等价入口
crypto --wizard
crypto wizard
```

向导会引导你选择中文或英文界面，输入或拖入文件/目录路径，选择加密或解密、算法、密码和输出保存路径。加密目录时会自动按递归目录加密处理；解密 `.enc` 文件时会优先从文件头识别算法。

### 命令风格（推荐记忆法）

```bash
# 加密：crypto [命令] [文件名] [命令] [加密后的文件名]
crypto encrypt secret.txt encrypt secret.txt.enc

# 解密：crypto [命令] [加密后的文件名] [命令] [解密后的文件名]
crypto decrypt secret.txt.enc decrypt secret.txt
```

### 1. 加密文件

```bash
# 使用密码加密文件（默认使用 AES-256-GCM）
crypto encrypt -i secret.txt -o secret.txt.enc

# 系统会提示输入密码
Enter password: ****
Confirm password: ****
✓ File encrypted successfully: secret.txt.enc
```

### 2. 解密文件

```bash
# 解密文件
crypto decrypt -i secret.txt.enc -o secret.txt

# 输入加密时使用的密码
Enter password: ****
✓ File decrypted successfully: secret.txt
```

### 3. 加密目录

```bash
# 递归加密整个目录
crypto encrypt -i my_folder -o my_folder.enc --recursive

# 目录会被打包成归档文件后加密
✓ Directory encrypted successfully: my_folder.enc
```

### 4. 查看支持的算法

```bash
# 列出所有支持的加密算法
crypto list-algorithms
```


## 使用方法

### 命令概览

```bash
crypto <COMMAND> [OPTIONS]
```

常用子命令别名（更短更好记）：
- `encrypt` → `e` / `enc`
- `decrypt` → `d` / `dec`
- `keygen` → `k` / `kg`
- `list-algorithms` → `ls` / `list` / `algos`
- `info` → `i`
- `wizard` 或 `-w, --wizard` → 交互式加密/解密向导

可用命令：
- `encrypt` - 加密文件或目录
- `decrypt` - 解密文件或目录
- `keygen` - 生成加密密钥
- `list-algorithms` - 列出支持的算法
- `info` - 显示加密文件信息
- `wizard` - 启动交互式加密/解密向导

### encrypt 命令

加密文件或目录。

```bash
crypto encrypt [OPTIONS] -i <FILE>
```

**选项：**

- `-i, --input <FILE>` - 要加密的输入文件或目录（必需）
- `-o, --output <FILE>` - 输出文件路径（默认：输入文件名 + .enc）
- `-a, --algorithm <ALGORITHM>` - 加密算法（默认：aes-256-gcm）
- `-k, --key-source <SOURCE>` - 密钥来源：password、env、keyfile（默认：password）
- `-p, --password-env <VAR>` - 密码环境变量名（当 key-source=env 时）
- `--keyfile <FILE>` - 密钥文件路径（当 key-source=keyfile 时）
- `-c, --compress <ALGORITHM>` - 压缩算法：gzip 或 zstd
- `--compression-level <LEVEL>` - 压缩级别（gzip: 1-9, zstd: 1-22）
- `-r, --recursive` - 递归加密目录
- `-v, --verbose` - 详细输出

**示例：**

```bash
# 使用默认算法加密
crypto encrypt -i document.pdf

# 使用 ChaCha20-Poly1305 加密
crypto encrypt -i data.txt -a chacha20-poly1305

# 加密前压缩
crypto encrypt -i large_file.dat -c zstd --compression-level 10

# 从环境变量读取密码
export MY_PASSWORD="secret123"
crypto encrypt -i file.txt -k env --password-env MY_PASSWORD

# 使用密钥文件加密
crypto encrypt -i file.txt -k keyfile --keyfile my.key

# 递归加密目录
crypto encrypt -i my_documents/ -o backup.enc -r
```


### decrypt 命令

解密文件或目录。

```bash
crypto decrypt [OPTIONS] -i <FILE>
```

**选项：**

- `-i, --input <FILE>` - 要解密的加密文件（必需）
- `-o, --output <FILE>` - 输出文件或目录路径（默认：移除 .enc 扩展名）
- `-k, --key-source <SOURCE>` - 密钥来源：password、env、keyfile（默认：password）
- `-p, --password-env <VAR>` - 密码环境变量名（当 key-source=env 时）
- `--keyfile <FILE>` - 密钥文件路径（当 key-source=keyfile 时）
- `-v, --verbose` - 详细输出

**示例：**

```bash
# 解密文件
crypto decrypt -i document.pdf.enc

# 指定输出路径
crypto decrypt -i encrypted.dat -o decrypted.dat

# 从环境变量读取密码
crypto decrypt -i file.enc -k env --password-env MY_PASSWORD

# 解密目录归档
crypto decrypt -i backup.enc -o restored_folder/
```

### keygen 命令

生成加密密钥或密钥对。

```bash
crypto keygen [OPTIONS] -a <ALGORITHM> -o <FILE>
```

**选项：**

- `-a, --algorithm <ALGORITHM>` - 算法类型（必需）
- `-o, --output <FILE>` - 输出文件路径（必需）
- `-f, --format <FORMAT>` - 导出格式：raw 或 pem（默认：pem）
- `-v, --verbose` - 详细输出

**示例：**

```bash
# 生成对称密钥（AES-256）
crypto keygen -a aes-256 -o my.key -f raw

# 生成 RSA 密钥对
crypto keygen -a rsa-4096 -o private.pem
# 会生成 private.pem 和 private.pub

# 生成 ECIES 密钥对
crypto keygen -a ecies-p256 -o ec_key.pem
```


### list-algorithms 命令

列出所有支持的加密算法及其属性。

```bash
crypto list-algorithms
```

### info 命令

显示加密文件的信息（不解密）。

```bash
crypto info -i <FILE>
```

**示例：**

```bash
crypto info -i encrypted_file.enc

# 输出示例：
# Algorithm: AES-256-GCM
# Compressed: Yes (zstd)
# KDF: Argon2id
# Original size: 1048576 bytes
```

## 支持的算法

### 对称加密算法（AEAD）

| 算法 | 密钥长度 | 安全性 | AEAD | 推荐 |
|------|---------|--------|------|------|
| **AES-256-GCM** | 256 位 | 高 | ✅ | ⭐ 推荐用于大多数场景 |
| **ChaCha20-Poly1305** | 256 位 | 高 | ✅ | ⭐ 推荐用于移动/嵌入式设备 |
| **AES-256-CBC** | 256 位 | 高 | ❌ (使用 HMAC) | 仅用于兼容性 |

### 非对称加密算法

| 算法 | 密钥长度 | 安全性 | 推荐 |
|------|---------|--------|------|
| **RSA-OAEP-2048** | 2048 位 | 中高 | 新应用最低要求 |
| **RSA-OAEP-4096** | 4096 位 | 很高 | ⭐ 推荐用于长期安全 |
| **ECIES-P256** | P-256 曲线 | 高 | ⭐ 推荐用于高效加密 |

### 密钥派生函数（KDF）

| KDF | 特性 | 推荐 |
|-----|------|------|
| **Argon2id** | 内存困难，抗 GPU/ASIC 攻击 | ⭐ 默认，推荐 |
| **PBKDF2-SHA256** | 标准 KDF，广泛支持 | 仅用于兼容性 |

### 压缩算法

| 算法 | 级别范围 | 特性 |
|------|---------|------|
| **Gzip** | 1-9 | 标准压缩，良好兼容性 |
| **Zstd** | 1-22 | 现代压缩，更好的压缩比和速度 |


## 示例

### 场景 1：加密敏感文档

```bash
# 使用强密码加密文档
crypto encrypt -i confidential.pdf -o confidential.pdf.enc

# 使用 RSA 公钥加密（无需密码）
crypto keygen -a rsa-4096 -o my_key.pem
crypto encrypt -i confidential.pdf -a rsa-oaep-4096 \
  -k keyfile --keyfile my_key.pub
```

### 场景 2：备份整个项目

```bash
# 加密整个项目目录，使用压缩节省空间
crypto encrypt -i my_project/ -o project_backup.enc \
  --recursive -c zstd --compression-level 15

# 恢复项目
crypto decrypt -i project_backup.enc -o restored_project/
```

### 场景 3：自动化脚本中使用

```bash
#!/bin/bash

# 从环境变量读取密码，避免交互式输入
export BACKUP_PASSWORD="your-secure-password"

# 加密多个文件
for file in *.txt; do
    crypto encrypt -i "$file" -o "${file}.enc" \
      -k env --password-env BACKUP_PASSWORD -v
done

# 清除环境变量
unset BACKUP_PASSWORD
```

### 场景 4：大文件加密

```bash
# 加密大文件（使用流式处理，内存占用恒定）
crypto encrypt -i large_video.mp4 -o large_video.mp4.enc \
  -a chacha20-poly1305 -v

# 工具会显示进度条
# [====================] 100% (1073741824/1073741824 bytes)
```

### 场景 5：查看加密文件信息

```bash
# 不解密，仅查看文件信息
crypto info -i encrypted_file.enc

# 输出：
# Encrypted File Information:
# Algorithm: AES-256-GCM
# KDF: Argon2id (100000 iterations)
# Compressed: Yes (zstd)
# Original size: 2048576 bytes
# Encrypted size: 1534892 bytes
```


## 安全注意事项

### 密码安全

- ✅ **使用强密码**：至少 12 个字符，包含大小写字母、数字和特殊字符
- ✅ **不要重复使用密码**：每个重要文件使用不同的密码
- ⚠️ **环境变量风险**：从环境变量读取密码后，密码可能仍保留在进程环境中
- ⚠️ **避免在命令行中直接输入密码**：使用交互式提示或环境变量

### 密钥管理

- 🔐 **妥善保管密钥文件**：密钥文件丢失将无法解密数据
- 🔐 **备份密钥**：将密钥文件安全备份到多个位置
- 🔐 **限制文件权限**：
  ```bash
  chmod 600 my_private_key.pem  # 仅所有者可读写
  ```
- 🔐 **定期轮换密钥**：对于长期存储的数据，考虑定期更换密钥

### 算法选择

- ⭐ **默认选择**：AES-256-GCM 适用于大多数场景
- ⭐ **移动设备**：ChaCha20-Poly1305 在移动设备上性能更好
- ⭐ **长期安全**：RSA-4096 或 ECIES-P256 用于需要长期保密的数据
- ❌ **避免使用**：AES-256-CBC 仅用于兼容旧系统

### 数据完整性

- ✅ 所有 AEAD 算法（AES-GCM、ChaCha20-Poly1305）自动验证数据完整性
- ✅ 解密时会自动检测篡改，如果数据被修改会拒绝解密
- ✅ 加密文件头包含校验和，防止文件损坏

### 内存安全

- ✅ 敏感数据（密钥、密码）在内存中使用后自动清零
- ✅ 使用 Rust 的内存安全特性防止缓冲区溢出
- ✅ 流式处理大文件，避免将整个文件加载到内存

### 文件操作安全

- ✅ 加密操作不会修改原始文件（除非明确指定覆盖）
- ✅ 使用原子文件操作：先写入临时文件，成功后再重命名
- ✅ 失败时自动清理临时文件


## 加密文件格式

工具使用自定义的加密文件格式，包含所有必要的元数据：

```
┌─────────────────────────────────────────┐
│ 文件头                                   │
├─────────────────────────────────────────┤
│ 魔数 (8 字节): "CRYPTOOL"               │
│ 版本 (2 字节): 0x0001                   │
│ 算法 ID (1 字节)                        │
│ 标志 (1 字节): [压缩|保留|...]          │
│ KDF 算法 (1 字节)                       │
│ KDF 迭代次数 (4 字节)                   │
│ 盐长度 (1 字节)                         │
│ 盐 (可变长度)                           │
│ IV 长度 (1 字节)                        │
│ IV (可变长度)                           │
│ 原始大小 (8 字节)                       │
│ 元数据长度 (2 字节)                     │
│ 元数据 (JSON 格式)                      │
│ 头部校验和 (32 字节, SHA-256)           │
├─────────────────────────────────────────┤
│ 加密数据 (可变长度)                     │
├─────────────────────────────────────────┤
│ 认证标签/MAC (16-32 字节)               │
└─────────────────────────────────────────┘
```

这种格式确保：
- ✅ 文件自描述，包含所有解密所需信息
- ✅ 向前兼容，支持未来版本扩展
- ✅ 完整性保护，防止文件损坏和篡改

## 性能特性

### 流式处理

- 大文件使用 64KB 缓冲区进行流式处理
- 内存占用恒定，不受文件大小影响
- 适合加密 GB 级别的文件

### 并行处理

- 目录加密支持并行处理多个文件（计划中）
- 充分利用多核 CPU 性能

### 优化

- 针对 macOS 文件系统特性优化缓冲区大小
- 使用高性能的 Rust 加密库（ring、RustCrypto）
- 零拷贝操作减少内存分配


## 测试

项目包含全面的测试套件：

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test crypto_test
cargo test key_manager_test

# 运行测试并显示输出
cargo test -- --nocapture

# 运行属性测试（需要更长时间）
cargo test --release
```

测试覆盖：
- ✅ 加密/解密往返测试
- ✅ 认证标签验证
- ✅ 密钥派生确定性
- ✅ 流式加密一致性
- ✅ 文件格式序列化/反序列化
- ✅ 目录归档和提取
- ✅ 错误处理

## 故障排除

### 常见问题

**Q: 解密时提示 "Authentication failed"**

A: 可能的原因：
- 密码错误
- 文件被篡改或损坏
- 使用了错误的密钥文件

**Q: 加密大文件时速度很慢**

A: 建议：
- 使用 ChaCha20-Poly1305 算法（通常比 AES 快）
- 避免使用高压缩级别
- 确保有足够的磁盘空间

**Q: 无法加密目录**

A: 确保：
- 使用 `--recursive` 或 `-r` 标志
- 有足够的磁盘空间存储归档文件
- 对目录有读取权限

**Q: 密钥文件格式错误**

A: 确保：
- 对称密钥文件应为 32 字节的原始二进制数据
- 非对称密钥应使用 PEM 格式
- 使用 `keygen` 命令生成正确格式的密钥


## 开发

### 构建开发版本

```bash
# 调试构建
cargo build

# 发布构建（优化）
cargo build --release
```

### 代码检查

```bash
# 运行 Clippy（Rust linter）
cargo clippy

# 格式化代码
cargo fmt

# 检查代码而不构建
cargo check
```

### 添加新功能

项目使用模块化架构，添加新功能时：

1. 在相应模块中实现功能
2. 在 `tests/` 目录添加测试
3. 更新 CLI 参数（如需要）
4. 更新文档

## 项目管理

### 更新项目

#### 更新依赖项

```bash
# 检查过时的依赖
cargo outdated

# 更新所有依赖到最新兼容版本
cargo update

# 更新特定依赖
cargo update -p ring
```

#### 更新代码

```bash
# 拉取最新代码
git pull origin main

# 重新构建项目
cargo clean
cargo build --release

# 运行测试确保一切正常
cargo test
```

#### 版本升级

编辑 `Cargo.toml` 文件更新版本号：

```toml
[package]
name = "crypto-cli-tool"
version = "0.2.0"  # 更新版本号
edition = "2021"
```

然后重新构建：

```bash
cargo build --release
```

### 删除项目

#### 卸载已安装的二进制文件

如果使用 `cargo install` 安装了工具：

```bash
# 卸载工具
cargo uninstall crypto-cli-tool

# 验证已卸载
which crypto-cli-tool  # 应该找不到
```

#### 删除项目源代码

```bash
# 进入项目父目录
cd /path/to/parent/directory

# 删除整个项目目录
rm -rf crypto-cli-tool/

# 或者使用 trash（更安全，可恢复）
trash crypto-cli-tool/
```

#### 清理构建缓存

```bash
# 在项目目录中清理构建产物
cargo clean

# 这会删除 target/ 目录，释放磁盘空间
```

#### 清理全局 Cargo 缓存（可选）

```bash
# 查看 Cargo 缓存大小
du -sh ~/.cargo

# 清理未使用的缓存（需要 cargo-cache 工具）
cargo install cargo-cache
cargo cache --autoclean

# 或手动删除特定缓存
rm -rf ~/.cargo/registry/cache
rm -rf ~/.cargo/git/checkouts
```

### 备份和恢复

#### 备份项目

```bash
# 备份整个项目（不包括构建产物）
tar -czf crypto-cli-tool-backup.tar.gz \
  --exclude='target' \
  --exclude='.git' \
  crypto-cli-tool/

# 或使用 git 归档
cd crypto-cli-tool
git archive --format=tar.gz --output=../backup.tar.gz HEAD
```

#### 恢复项目

```bash
# 从备份恢复
tar -xzf crypto-cli-tool-backup.tar.gz

# 重新构建
cd crypto-cli-tool
cargo build --release
```

### 迁移到新系统

#### 导出配置和密钥

```bash
# 备份密钥文件
cp ~/.crypto-cli/*.key ~/backup/keys/

# 备份配置（如果有）
cp ~/.config/crypto-cli/* ~/backup/config/
```

#### 在新系统上安装

```bash
# 1. 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. 克隆或复制项目
git clone <repository-url>
# 或解压备份文件

# 3. 构建安装
cd crypto-cli-tool
cargo install --path .

# 4. 恢复密钥和配置
cp ~/backup/keys/* ~/.crypto-cli/
chmod 600 ~/.crypto-cli/*.key
```

## 依赖项

主要依赖：

- **ring** - 核心加密原语
- **aes-gcm** - AES-GCM 实现
- **chacha20poly1305** - ChaCha20-Poly1305 实现
- **argon2** - Argon2 密钥派生
- **rsa** - RSA 加密
- **p256** - ECIES 椭圆曲线加密
- **clap** - 命令行参数解析
- **zstd** / **flate2** - 压缩算法


## 贡献

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

## 致谢

本项目使用了以下优秀的开源库：
- RustCrypto 项目
- Ring 加密库
- Clap CLI 框架

---

**⚠️ 免责声明**：本工具仅供学习和研究目的。虽然使用了业界标准的加密算法和最佳实践，但作者不对数据丢失或安全问题承担责任。在生产环境使用前，请进行充分的安全审计。
