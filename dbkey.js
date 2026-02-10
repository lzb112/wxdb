// Frida script to hook setConfig and extract cipherKey
  // RVA: 0x12C57A0

  const MODULE_NAME = "Weixin.dll"; // 填写实际的模块名，如 "wcdb.dll" 或主程序名
  const SETCONFIG_RVA = 0x12C57A0;

  // Data 类内存布局 (继承自 UnsafeData)
  // - m_buffer: pointer (8 bytes)
  // - m_size: size_t (8 bytes)
  // - m_sharedBuffer: std::shared_ptr-like (16 bytes通常)

  function readDataObject(ptr) {
      if (ptr.isNull()) return null;

      // UnsafeData 布局:
      // offset 0: m_buffer (void*)
      // offset 8: m_size (size_t)
      const buffer = ptr.readPointer();
      const size = ptr.add(8).readU64();

      if (buffer.isNull() || size == 0) {
          return null;
      }

      // 读取密钥内容
      const keyBytes = buffer.readByteArray(Number(size));
      return {
          size: Number(size),
          buffer: buffer,
          hex: buffer.readByteArray(Number(size)).toString('hex'),
          bytes: keyBytes
      };
  }

  // CipherConfig 内存布局分析 (64位)
  // 从 Config 继承，有虚函数表
  // offset 0: vtable pointer
  // offset 8: m_key (Data)
  // offset 8+24=32: m_rawKey (Data) - 考虑对齐
  // 实际偏移可能需要根据编译器调整

  function readCipherKeyFromConfig(configPtr) {
      // CipherConfig 继承 Config -> 虚函数表在 offset 0
      // m_key 在 offset 8 (vtable之后)
      // m_rawKey 在 m_key 之后

      const m_key_offset = 8;  // vtable 之后
      const m_rawKey_offset = 8 + 24; // m_key 大小约24字节 (考虑对齐)

      // 尝试读取 m_key
      const keyData = readDataObject(configPtr.add(m_key_offset));
      const rawKeyData = readDataObject(configPtr.add(m_rawKey_offset));

      return {
          key: keyData,
          rawKey: rawKeyData
      };
  }

  function hookSetConfig() {
      const module = Process.findModuleByName(MODULE_NAME);
      if (!module) {
          console.error("[-] Module not found:", MODULE_NAME);
          console.log("[*] Available modules:");
          Process.enumerateModules().forEach(m => console.log("  - " + m.name));
          return;
      }

      const setConfigAddr = module.base.add(SETCONFIG_RVA);
      console.log("[+] setConfig address:", setConfigAddr);

      // 分析函数签名 (x64 Windows)
      // setConfig(const std::string& name, std::shared_ptr<Config> config, Priority priority)
      // RCX: this
      // RDX: &name (std::string)
      // R8: config._Ptr (std::shared_ptr<Config> 的内部指针)
      // R9: priority

      Interceptor.attach(setConfigAddr, {
          onEnter: function(args) {
              const thisPtr = args[0];           // RCX
              const namePtr = args[1];           // RDX - std::string*
              const configPtr = args[2];         // R8 - Config* (shared_ptr内部)
              const priority = args[3];          // R9

              // 读取配置名称
              let configName = "unknown";
              if (!namePtr.isNull()) {
                  // std::string SSO 布局: 前16字节可能是内联buffer或指针
                  // 简单尝试读取
                  try {
                      const strSize = namePtr.add(16).readU64(); // 通常size在offset 16
                      if (strSize < 16) {
                          // SSO 模式，数据在内部
                          configName = namePtr.readCString();
                      } else {
                          // 堆分配模式
                          const strPtr = namePtr.readPointer();
                          configName = strPtr.readCString();
                      }
                  } catch(e) {
                      configName = namePtr.readCString() || "error";
                  }
              }

              console.log("\n[+] setConfig called");
              console.log("    this:", thisPtr);
              console.log("    config name:", configName);
              console.log("    config ptr:", configPtr);
              console.log("    priority:", priority);

              // 检查是否是 CipherConfig
              if (configName.includes("Cipher") || configName === "WCDB.CipherConfigName") {
                  console.log("[*] Found CipherConfig!");

                  // 读取虚函数表来确认类型 (可选)
                  const vtable = configPtr.readPointer();
                  console.log("    vtable:", vtable);

                  // 读取密钥
                  const keys = readCipherKeyFromConfig(configPtr);

                  if (keys.key) {
                      console.log("[+] m_key found:");
                      console.log("    size:", keys.key.size);
                      console.log("    hex:", keys.key.hex);
                      console.log("    string:", keys.key.buffer.readCString());
                  }

                  if (keys.rawKey) {
                      console.log("[+] m_rawKey found:");
                      console.log("    size:", keys.rawKey.size);
                      console.log("    hex:", keys.rawKey.hex);
                  }

                  // 如果是十六进制密钥格式 (x'...')，特殊处理
                  if (keys.key && keys.key.size > 0) {
                      const keyStr = keys.key.buffer.readCString(keys.key.size);
                      if (keyStr && keyStr.startsWith("x'")) {
                          console.log("[*] Hex format key detected");
                      }
                  }
              }
          },

          onLeave: function(retval) {
              // 可选：检查返回值
          }
      });

      console.log("[+] Hook installed at", setConfigAddr);
  }

  // 主函数
  console.log("[*] WCDB setConfig hook started");
  console.log("[*] Target RVA: 0x" + SETCONFIG_RVA.toString(16));

  // 等待模块加载
  function waitForModule() {
      const module = Process.findModuleByName(MODULE_NAME);
      if (module) {
          hookSetConfig();
      } else {
          console.log("[*] Waiting for module:", MODULE_NAME);
          setTimeout(waitForModule, 1000);
      }
  }

  // 如果模块已经加载，直接hook；否则等待
  waitForModule();

  // 也可以通过模块加载事件监听
  Process.on('module-loaded', function(module) {
      console.log("[*] Module loaded:", module.name);
      if (module.name.toLowerCase().includes(MODULE_NAME.toLowerCase())) {
          console.log("[+] Target module loaded!");
          hookSetConfig();
      }
  });
