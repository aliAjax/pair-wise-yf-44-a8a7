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

- `unit`：装置运行状态；`change`：变更申请；`action_item`：风险控制行动项。
- `interlock_bypass`：联锁旁路，纳入变更流程管理（见下）。

## 联锁旁路流程

旁路由**操作员**提出，必填装置、联锁位号、恢复期限（不早于当天）和恢复责任人，并关联到一个未终结的变更。提交后为 `pending_review`（待复核），**安全员复核**后方可 `active`（生效）。

生效期间遇到以下任一情形，旁路自动转为 `reconfirm_required`（待重新签认），须安全员重新签认才能回到生效状态，签认记录保留：

- 变更风险被 `escalate_risk` 升级；
- 受影响装置被 `shutdown` 停机；
- `reassign_owner` 更换恢复责任人。

旁路在以下情形自动转为 `invalidated`（已失效），历史记录与审计仍保留：

- 到达恢复期限仍未恢复（读取 / 动作 / 投产检查时惰性扫描，时钟可注入便于测试）；
- 变更被 `reject` 拒绝、`withdraw` 撤回或 `close` 关闭（级联失效）。

旁路可由操作员 / 安全员 `recover` 恢复为 `recovered`。

投产（`commission`）前会汇总具体阻塞项：未验证的行动项，以及任何未恢复的旁路（待复核、生效中、待重新签认、已失效）。可用 `GET /api/entities/<change_id>/blockers` 查询阻塞清单；直接投产返回包含具体 ID 与原因的校验错误。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤（`interlock_bypasses`为旁路）。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `GET /api/entities/<id>/blockers`：查询变更的投产阻塞项。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

旁路动作：`review`（安全员复核）、`reconfirm`（重新签认）、`recover`（恢复）、`reassign_owner`（更换恢复责任人）；变更动作另增 `reject`、`withdraw`、`escalate_risk`。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

风险分级和投产规则用于流程演示，不替代HAZOP、LOPA、法定许可和现场安全审查。
