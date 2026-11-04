# Angular 前端

源码在 `src/`，依赖由 `package.json` 和 `package-lock.json` 固定。Angular 管理页面、图表、表格、规则编辑和详情交互；ECharts 按需打包为本地分包。

在项目根目录运行 `python -B preview.py` 可构建临时资源并启动回环地址的合成数据预览。构建使用 `python -B build_frontend.py --output <源码树外目录>`，完整发布包通过 `deploy.ps1 -BuildOnly -OutputDirectory <源码树外目录>` 导出。部署与访问说明见 [部署文档](../README-deploy.md)。

生成的 ATT&CK 目录、依赖、缓存与生产产物不作为源码保存。构建包含内容哈希、来源清单和前端回归；发行资源应保留 `frontend-licenses.txt`。

共享组件处理分页、选择、列宽、弹窗和滚动恢复。实时请求替换旧订阅并忽略迟到响应；查询条件由后端 schema 提供。连接按引擎 session_id 关联，缺少 ID 时不推测合并。

桌面浏览器回归位于 `tests/angular-*.mjs`，使用隔离预览，不连接生产引擎。界面文案、连接徽标和来源样式约定见 [AGENTS.md](../AGENTS.md)。
