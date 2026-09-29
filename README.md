# 化工装置变更与工艺安全管理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8310`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务和乐观锁。
- `src/service.py`：用例编排、幂等处理、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8310
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `unit`：装置运行状态；`change`：变更申请；`action_item`：风险控制行动项；
  `interlock_bypass`：安全联锁临时旁路（纳入变更流程管理）。

## 联锁旁路流程

1. **提出（operator）**：创建 `interlock_bypass`，必须填写装置 `unit_id`、所属变更
   `change_id`、联锁位号 `interlock_tag`、恢复期限 `restore_deadline`（ISO 日期，不早于当天）
   和恢复责任人 `restore_owner`。初始状态 `pending_review`，同一变更下同一位号已有未了结旁路时拒绝创建。
2. **复核（safety）**：`approve_bypass`（附风险复核意见）后状态变为 `active` 才生效；
   也可 `reject_bypass`，操作员可 `cancel` 撤回申请。
3. **重新签认**：生效期间发生 ① 变更风险升级（`report_event` + `new_risk_level` 须高于批准时等级）、
   ② 影响装置停机（装置执行 `shutdown` 时自动挂起）、③ 恢复责任人更换（`change_owner`），
   旁路进入 `pending_resign`，由安全员 `resign` 重新签认后方恢复生效；挂起期间不能恢复。
4. **自动失效（记录保留）**：到达恢复期限后懒触发自动置为 `expired`；
   变更被 `reject`、`withdraw`、`close` 时，其下未恢复旁路自动置为 `auto_invalidated`。
   两种情况都可用 `recover` 补办恢复，历史数据与审计记录均保留。
5. **投产阻塞**：`GET /api/changes/<id>/blockers` 返回结构化阻塞项；
   存在未恢复旁路（待复核/生效中/待签认/到期未恢复/随变更失效未恢复）时，
   `commission` 动作失败并在错误信息中逐一列出联锁位号与原因。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤（`bypasses` 为联锁别号）。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/changes/<id>/blockers`：投产前具体阻塞项（行动项 + 未恢复旁路）。
- `GET /api/audit`：读取审计记录（含 `auto_expire`、`auto_invalidate`、`auto_require_resign` 系统动作）。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

风险分级和投产规则用于流程演示，不替代HAZOP、LOPA、法定许可和现场安全审查。
