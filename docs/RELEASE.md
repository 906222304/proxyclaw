# Windows 自动打包与 Release

GitHub Actions 工作流：`.github/workflows/release.yml`。

## 日常构建

- 推送 `main` 或对 `main` 提交 PR：构建并测试，生成 Actions artifact，不创建 Release。
- 在 Actions 的 **Windows build and release → Run workflow** 手动运行：
  `tag` 留空且 `publish_release=false` 时，只生成当前所选分支的快照包。
- artifact 名称为 `windows-x64`，包含完整 ZIP 和 SHA256 校验文件，保留 14 天。

## 发布正式版本

在准备发布的 `main` 提交上创建版本标签并推送：

```powershell
git switch main
git pull --ff-only
git tag v0.10.1
git push origin v0.10.1
```

`v0.10.1` 是示例，请使用尚未存在的版本号。推送标签后，工作流完成构建、
测试和打包，再创建对应 GitHub Release。`v0.10.1-rc.1` 这类标签会生成预发布。

也可以手动输入**已存在的版本标签**并勾选 `publish_release`。此时只构建该标签，
不创建或移动 Git 标签。已有 Release 的同名附件会被此次成功构建替换。

发布产物：

```text
proxyclaw-v0.10.1-windows-x64.zip
proxyclaw-v0.10.1-windows-x64.zip.sha256
```

完整解压后运行 `proxyclaw.exe`。ZIP 包含 `frontend/dist`、WinDivert 运行库、
项目说明及第三方许可证。CI 不打包个人 `proxyclaw.json`、日志、账户数据或转储。

## 构建过程

1. Python 3.12 与 Node.js 22；Actions 固定到完整提交 SHA。
2. `scripts/prepare_release_deps.py` 下载并校验四个固定版本的头文件依赖和
   官方 WinDivert 2.2.2 SDK，解压仓库内已有的 WebView2 SDK。
3. CMake 生成版本常量；`npm ci` 使用 lockfile 安装并构建前端。
4. Visual Studio 2022 x64 Release 构建，静态链接 MSVC 运行时；CTest 运行
   包元组、网卡、FIN/ACK、端口复用及校验和回归，不打开驱动。
5. `scripts/package_local.py` 校验首页引用的资源并生成完整 ZIP。
6. 构建任务只有 `contents: read`；发布任务在构建成功后才使用 `contents: write`。

CI 不执行需要管理员权限的全机透明转发实验。本机的 live 集成测试需在退出
其他 ProxyClaw 实例后单独运行。

## 本机复用 CI 依赖

```powershell
python scripts/prepare_release_deps.py
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_PREFIX_PATH="$PWD/build/release-deps/prefix" `
  -DWEBVIEW2_PATH="$PWD/build/release-deps/webview2" `
  -DPROXYCLAW_WINDIVERT_DIR="$PWD/build/release-deps/WinDivert-2.2.2-A/x64" `
  -DPROXYCLAW_ENABLE_WEBVIEW2=ON -DBUILD_TESTING=ON
Push-Location frontend
npm ci
npm run build
Pop-Location
cmake -S . -B build
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure
python scripts/package_local.py --build-dir build/Release --frontend-dist frontend/dist --output-dir dist/proxyclaw-local-windows-x64 --version local
```

本机安装 Visual Studio 2026 时，可将生成器替换为 `Visual Studio 18 2026`。
