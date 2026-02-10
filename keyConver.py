import hashlib
import os
import sys


def convert_to_sqlcipher_rawkey(key_hex: str, file_path: str, is_v4: bool = True) -> str:
    """
    将微信密钥转换为 SQLCipher Raw Key (0x...)
    对应 Rust 代码中的 convert_to_sqlcipher_rawkey 函数

    Args:
        key_hex: 十六进制格式的密钥字符串 (64字符，32字节)，如从微信内存 dump 出的 key
        file_path: 数据库文件路径，用于提取前 16 字节作为 salt
        is_v4: True 为 SQLCipher 4 (默认), False 为 SQLCipher 3

    Returns:
        0x 开头的 64 字符十六进制字符串 (32字节)
        可直接用于: PRAGMA key = "0x...";
    """
    # 检查文件存在
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"文件不存在: {file_path}")

    # 读取文件前 16 字节作为 salt (SQLCipher 文件头格式)
    with open(file_path, 'rb') as f:
        salt = f.read(16)

    if len(salt) != 16:
        raise ValueError(f"无法读取有效的 salt，文件可能损坏或过小")

    # 清理密钥格式 (去除 0x 前缀、空格等)
    key_hex = key_hex.strip().replace(" ", "").replace("0x", "").replace("0X", "")

    if len(key_hex) != 64:
        raise ValueError(f"密钥长度错误，期望 64 字符 (32字节)，实际 {len(key_hex)} 字符")

    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("密钥包含非法十六进制字符")

    # 根据 SQLCipher 版本选择参数
    if is_v4:
        # SQLCipher 4 默认: PBKDF2-HMAC-SHA512, 256000 次迭代
        hash_name = 'sha512'
        iterations = 256000
    else:
        # SQLCipher 3 默认: PBKDF2-HMAC-SHA1, 4000 次迭代
        hash_name = 'sha1'
        iterations = 4000

    # 执行 PBKDF2 密钥派生
    # SQLCipher 使用提供的 key 作为 password，文件头作为 salt
    derived_key = hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=key_bytes,  # 微信内存中的 key 作为 password 输入
        salt=salt,  # 数据库文件头 16 字节
        iterations=iterations,  # 迭代次数
        dklen=32  # 输出 32 字节 (256 位 AES 密钥)
    )

    # 返回 SQLCipher Raw Key 格式: 0x + 64 字符十六进制
    return "0x" + derived_key.hex()


# 使用示例 (对应你的命令行)
if __name__ == "__main__":
    key = "" #hook出来的hexkey
    file_path = r"E:\xwechat_files\wxid_xxxxxx\db_storage\message\message_resource.db"

    try:
        # --vv 4 (默认，SQLCipher 4)
        raw_key_v4 = convert_to_sqlcipher_rawkey(key, file_path, is_v4=True)
        print(f"SQLCipher 4 Raw Key: {raw_key_v4}")

        # 如果是 --vv 3 (旧版微信)
        # raw_key_v3 = convert_to_sqlcipher_rawkey(key, file_path, is_v4=False)
        # print(f"SQLCipher 3 Raw Key: {raw_key_v3}")

    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
