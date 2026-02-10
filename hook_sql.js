// Frida script to hook sqlite3_prepare_v2 and sqlite3_bind_* functions
// to trace all SQL statements and their bound parameters

const MODULE_NAME = "Weixin.dll"; // 填写实际的模块名

// RVA 常量
const SQLITE3_PREPARE_V2_RVA = 0x4BC3110;
const SQLITE3_BIND_BLOB_RVA = 0x4B9D980;
const SQLITE3_BIND_DOUBLE_RVA = 0x4B9DAE0;
const SQLITE3_BIND_INT_RVA = 0x4B9DC60;
const SQLITE3_BIND_INT64_RVA = 0x4B9DC70;
const SQLITE3_BIND_NULL_RVA = 0x4B9DCC0;
const SQLITE3_BIND_TEXT_RVA = 0x4B9DD70;
const SQLITE3_STEP_RVA = 0x4B9CF60;
const SQLITE3_FINALIZE_RVA = 0x4B9C760;

// 存储 stmt -> SQL 的映射
const stmtSQLMap = new Map();
let currentSQL = null;
let currentIsInsert = false;

function hookSqliteFunctions() {
    const module = Process.findModuleByName(MODULE_NAME);
    if (!module) {
        console.error("[-] Module not found:", MODULE_NAME);
        console.log("[*] Available modules:");
        Process.enumerateModules().forEach(m => console.log("  - " + m.name));
        return;
    }

    console.log("[+] Module base address:", module.base);

    // Hook sqlite3_prepare_v2
    hookPrepareV2(module);

    // Hook bind functions
    hookBindBlob(module);
    hookBindDouble(module);
    hookBindInt(module);
    hookBindInt64(module);
    hookBindNull(module);
    hookBindText(module);

    // Hook sqlite3_step
    hookStep(module);

    // Hook sqlite3_finalize
    hookFinalize(module);

    console.log("[+] All hooks installed");
}

function hookPrepareV2(module) {
    const addr = module.base.add(SQLITE3_PREPARE_V2_RVA);
    console.log("[+] sqlite3_prepare_v2 at:", addr);

    // sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte,
    //                    sqlite3_stmt **ppStmt, const char **pzTail)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.db = args[0];
            this.sqlPtr = args[1];
            this.nByte = args[2].toInt32();
            this.ppStmt = args[3];
        },
        onLeave: function(retval) {
            const result = retval.toInt32();
            if (result !== 0 || this.sqlPtr.isNull()) {
                return;
            }

            let sql = "";
            try {
                if (this.nByte < 0) {
                    sql = this.sqlPtr.readUtf8String();
                } else {
                    sql = this.sqlPtr.readUtf8String(this.nByte);
                }
            } catch(e) {
                sql = "[Error: " + e.message + "]";
            }

            // 读取返回的 stmt 句柄
            let stmt = null;
            if (!this.ppStmt.isNull()) {
                stmt = this.ppStmt.readPointer();
            }

            // 存储 SQL 与 stmt 的关联
            if (stmt && !stmt.isNull()) {
                stmtSQLMap.set(stmt.toString(), sql);
            }

            // 检查是否是 INSERT
            const isInsert = sql && sql.trim().toUpperCase().startsWith("INSERT");

            if (isInsert) {
                currentSQL = sql;
                currentIsInsert = true;
                console.log("\n[+] INSERT Prepare:");
                console.log("    SQL:", sql);
                console.log("    Stmt:", stmt);
            } else {
                currentIsInsert = false;
            }
        }
    });
}

function hookBindBlob(module) {
    const addr = module.base.add(SQLITE3_BIND_BLOB_RVA);
    console.log("[+] sqlite3_bind_blob at:", addr);

    // sqlite3_bind_blob(stmt, index, data, n, destructor)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();
            const data = args[2];
            const n = args[3].toInt32();

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                let hex = "";
                try {
                    if (!data.isNull() && n > 0) {
                        const bytes = data.readByteArray(Math.min(n, 32));
                        hex = bytes ? Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0')).join('') : "";
                        if (n > 32) hex += "...";
                    }
                } catch(e) {
                    hex = "[Error]";
                }
                console.log("    [Bind Blob] Index:", index, "Size:", n, "Data:", hex ? "0x" + hex : "null");
            }
        }
    });
}

function hookBindDouble(module) {
    const addr = module.base.add(SQLITE3_BIND_DOUBLE_RVA);
    console.log("[+] sqlite3_bind_double at:", addr);

    // sqlite3_bind_double(stmt, index, value)
    // Windows x64: double 通过 XMM2 传递
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                // double 值在 XMM2，但 Frida 可能无法直接读取
                // 尝试从内存或其他方式获取
                console.log("    [Bind Double] Index:", index);
            }
        }
    });
}

function hookBindInt(module) {
    const addr = module.base.add(SQLITE3_BIND_INT_RVA);
    console.log("[+] sqlite3_bind_int at:", addr);

    // sqlite3_bind_int(stmt, index, value)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();
            const value = args[2].toInt32();

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                console.log("    [Bind Int] Index:", index, "Value:", value);
            }
        }
    });
}

function hookBindInt64(module) {
    const addr = module.base.add(SQLITE3_BIND_INT64_RVA);
    console.log("[+] sqlite3_bind_int64 at:", addr);

    // sqlite3_bind_int64(stmt, index, value)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();
            const value = args[2]; // 64-bit

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                console.log("    [Bind Int64] Index:", index, "Value:", value.toString());
            }
        }
    });
}

function hookBindNull(module) {
    const addr = module.base.add(SQLITE3_BIND_NULL_RVA);
    console.log("[+] sqlite3_bind_null at:", addr);

    // sqlite3_bind_null(stmt, index)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                console.log("    [Bind Null] Index:", index);
            }
        }
    });
}

function hookBindText(module) {
    const addr = module.base.add(SQLITE3_BIND_TEXT_RVA);
    console.log("[+] sqlite3_bind_text at:", addr);

    // sqlite3_bind_text(stmt, index, text, n, destructor)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const stmt = args[0];
            const index = args[1].toInt32();
            const textPtr = args[2];
            const n = args[3].toInt32();

            const sql = stmtSQLMap.get(stmt.toString());
            if (sql && sql.trim().toUpperCase().startsWith("INSERT")) {
                let text = "";
                try {
                    if (!textPtr.isNull()) {
                        if (n < 0) {
                            text = textPtr.readUtf8String();
                        } else {
                            text = textPtr.readUtf8String(n);
                        }
                    }
                } catch(e) {
                    text = "[Error: " + e.message + "]";
                }
                console.log("    [Bind Text] Index:", index, "Value:", text);
            }
        }
    });
}

function hookStep(module) {
    const addr = module.base.add(SQLITE3_STEP_RVA);
    console.log("[+] sqlite3_step at:", addr);

    // sqlite3_step(stmt)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.stmt = args[0];
            this.sql = stmtSQLMap.get(this.stmt.toString());

            if (this.sql && this.sql.trim().toUpperCase().startsWith("INSERT")) {
                console.log("    [*] INSERT Step executing...");
            }
        },
        onLeave: function(retval) {
            const result = retval.toInt32();

            if (this.sql && this.sql.trim().toUpperCase().startsWith("INSERT")) {
                // SQLITE_DONE = 101, SQLITE_ROW = 100
                if (result === 100) {
                    console.log("    [+] INSERT Step result: SQLITE_ROW (has more rows)");
                } else if (result === 101) {
                    console.log("    [+] INSERT Step result: SQLITE_DONE (completed)");
                } else if (result === 0) {
                    console.log("    [+] INSERT Step result: SQLITE_OK (success)");
                } else {
                    console.log("    [+] INSERT Step result:", result);
                }

            }
        }
    });
}

function hookFinalize(module) {
    const addr = module.base.add(SQLITE3_FINALIZE_RVA);
    console.log("[+] sqlite3_finalize at:", addr);

    // sqlite3_finalize(stmt)
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.stmt = args[0];
            this.sql = stmtSQLMap.get(this.stmt.toString());
        },
        onLeave: function(retval) {
            const result = retval.toInt32();

            if (this.sql && this.sql.trim().toUpperCase().startsWith("INSERT")) {
                if (result === 0) {
                    console.log("    [+] INSERT Finalized successfully");
                } else {
                    console.log("    [-] INSERT Finalize error:", result);
                }
            }

            // 清理 stmt 映射，防止内存泄漏
            if (this.stmt && !this.stmt.isNull()) {
                stmtSQLMap.delete(this.stmt.toString());
            }
        }
    });
}

// 主函数
console.log("[*] WCDB SQL Hook started");
console.log("[*] Target module:", MODULE_NAME);

// 等待模块加载
function waitForModule() {
    const module = Process.findModuleByName(MODULE_NAME);
    if (module) {
        hookSqliteFunctions();
    } else {
        console.log("[*] Waiting for module:", MODULE_NAME);
        setTimeout(waitForModule, 1000);
    }
}

// 标记是否已 hook，防止重复
let isHooked = false;

function tryHook() {
    if (isHooked) return;

    const module = Process.findModuleByName(MODULE_NAME);
    if (module) {
        isHooked = true;
        hookSqliteFunctions();
    } else {
        setTimeout(tryHook, 1000);
    }
}

// 开始尝试 hook
tryHook();
