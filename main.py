# -*- coding: utf-8 -*-
import asyncio
import hashlib
import os
import random
import re
import shutil
import string
import subprocess
import unicodedata

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
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")
TEMP_WORK_DIR = os.path.join(BASE_DIR, "temp_work")
UNSIGNED_APK_PATH = os.path.join(BASE_DIR, "rebuilt_game-unsigned.apk")
ALIGNED_APK_PATH = os.path.join(BASE_DIR, "rebuilt_game-aligned.apk")
OUTPUT_APK_PATH = os.path.join(BASE_DIR, "rebuilt_game.apk")
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
    "android.permission.INTERNET",
    "android.permission.READ_PHONE_STATE",
    "com.google.firebase.analytics",
    "android.app.NotificationManager",
    "javax.net.ssl.TrustManagerFactory",
    "android.hardware.camera2.CameraManager",
    "com.android.internal.util.Preconditions",
    "android.os.Build.VERSION.SDK_INT",
    "android.content.pm.PackageManager",
    "android.telephony.TelephonyManager",
]

dp = Dispatcher()


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
        issues.append(f"{env_name} содержит пробел в начале или в конце.")

    invisible_codes = []
    for char in value:
        if char in {"\u00A0", "\u200B", "\u200C", "\u200D", "\uFEFF"}:
            invisible_codes.append(f"U+{ord(char):04X}")
            continue

        if unicodedata.category(char) == "Cf":
            invisible_codes.append(f"U+{ord(char):04X}")

    if invisible_codes:
        unique_codes = ", ".join(sorted(set(invisible_codes)))
        issues.append(f"{env_name} содержит невидимые символы ({unique_codes}).")

    return issues


def build_keystore_troubleshooting(*, include_key_password=True):
    hints = [
        "Предупреждение про JKS и PKCS12 само по себе не является ошибкой: JKS старый, но рабочий формат.",
        f"Проверьте, что используется именно этот keystore: '{KS_PATH}'.",
    ]

    if KS_TYPE:
        hints.append(f"Для подписи используется тип хранилища KS_TYPE={KS_TYPE}.")
    else:
        hints.append("Если это JKS-файл на Linux/новом Java, задайте KS_TYPE=JKS.")

    if KS_PASS_ENCODING:
        hints.append(f"Для подписи используется кодировка пароля KS_PASS_ENCODING={KS_PASS_ENCODING}.")
    elif any(ord(char) > 127 for char in f"{KS_PASS}{KS_KEY_PASS}"):
        hints.append("Если пароль содержит не-ASCII символы, попробуйте задать KS_PASS_ENCODING=utf-8.")

    hints.extend(describe_secret_issues("KS_PASS", KS_PASS))

    if include_key_password:
        hints.append(
            "Если keytool принимает KS_PASS, а подпись все равно падает, проверьте отдельный пароль ключа KS_KEY_PASS."
        )
        hints.extend(describe_secret_issues("KS_KEY_PASS", KS_KEY_PASS))

    return "\n".join(f"- {hint}" for hint in hints)


def format_keystore_error(summary, *, details="", include_key_password=True):
    parts = [summary, "", build_keystore_troubleshooting(include_key_password=include_key_password)]
    if details:
        parts.extend(["", f"Детали утилиты: {details}"])
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
                    "Не удалось открыть keystore через keytool.",
                    details=exc.details,
                    include_key_password=False,
                )
            ) from exc
        if "alias <" in message and "does not exist" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    f"В keystore '{KS_PATH}' не найден alias '{KS_ALIAS}'.",
                    details=exc.details,
                    include_key_password=False,
                )
            ) from exc
        raise KeystoreConfigError(
            format_keystore_error("Не удалось проверить keystore.", details=exc.details)
        ) from exc


    if REQUIRE_SHA256_KEYSTORE:
        details = combine_process_output(result.stdout, result.stderr).replace(" ", "").lower()
        if "signaturealgorithmname:sha256" not in details:
            raise KeystoreConfigError(
                "Сертификат keystore должен использовать SHA-256. Пересоздайте его командой "
                "'keytool -genkey -sigalg SHA256withRSA ...' или отключите "
                "REQUIRE_SHA256_KEYSTORE."
            )


def xor_encrypt_bytes(text, key):
    """XOR-encrypt a UTF-8 string with a per-class single-byte key."""
    return [b ^ key for b in text.encode("utf-8")]


def generate_encrypted_smali(class_name, method_name, fake_string, key):
    """Return smali source for a class that stores an XOR-encrypted string
    and exposes a static decrypt() method that reconstructs it at runtime."""
    encrypted = xor_encrypt_bytes(fake_string, key)
    length = len(encrypted)
    byte_data = "\n        ".join(f"0x{b:02x}" for b in encrypted)
    class_ref = f"Lcom/security/guard/{class_name};"
    return (
        f".class public {class_ref}\n"
        f".super Ljava/lang/Object;\n"
        f"\n"
        f".field private static final ENCRYPTED:[B\n"
        f"\n"
        f".method static constructor <clinit>()V\n"
        f"    .registers 2\n"
        f"    const/16 v0, {length}\n"
        f"    new-array v0, v0, [B\n"
        f"    fill-array-data v0, :enc_data\n"
        f"    sput-object v0, {class_ref}->ENCRYPTED:[B\n"
        f"    return-void\n"
        f"\n"
        f"    :enc_data\n"
        f"    .array-data 1\n"
        f"        {byte_data}\n"
        f"    .end array-data\n"
        f".end method\n"
        f"\n"
        f".method public constructor <init>()V\n"
        f"    .registers 1\n"
        f"    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V\n"
        f"    return-void\n"
        f".end method\n"
        f"\n"
        f"# XOR key: 0x{key:02x}  (per-class, embedded in decrypt method)\n"
        f".method public static {method_name}()[B\n"
        f"    .registers 6\n"
        f"    sget-object v0, {class_ref}->ENCRYPTED:[B\n"
        f"    array-length v1, v0\n"
        f"    new-array v2, v1, [B\n"
        f"    const/4 v3, 0x0\n"
        f"    const/16 v4, 0x{key:02x}\n"
        f"    :loop\n"
        f"    if-ge v3, v1, :end\n"
        f"    aget-byte v5, v0, v3\n"
        f"    xor-int/2addr v5, v4\n"
        f"    int-to-byte v5, v5\n"
        f"    aput-byte v5, v2, v3\n"
        f"    add-int/lit8 v3, v3, 0x1\n"
        f"    goto :loop\n"
        f"    :end\n"
        f"    return-object v2\n"
        f".end method\n"
    )


def inject_security_measures(work_dir):
    print("🔒 Применение защиты кода...")

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

    fake_package_path = os.path.join(work_dir, "smali", "com", "security", "guard")
    os.makedirs(fake_package_path, exist_ok=True)

    for _ in range(5):
        class_name = generate_random_string(8)
        method_name = generate_random_string(6)
        key = random.randint(1, 255)
        fake_string = random.choice(FAKE_STRINGS)

        smali_content = generate_encrypted_smali(class_name, method_name, fake_string, key)
        smali_file = os.path.join(fake_package_path, f"{class_name}.smali")
        with open(smali_file, "w", encoding="utf-8") as file:
            file.write(smali_content)


def sign_apk(unsigned_apk, output_apk, *, env=None):
    remove_file_if_exists(ALIGNED_APK_PATH)
    remove_file_if_exists(output_apk)

    run_command(
        [ZIPALIGN_PATH, "-f", "-p", "4", unsigned_apk, ALIGNED_APK_PATH],
        "zipalign",
        env=env,
    )

    try:
        run_command(build_apksigner_command(ALIGNED_APK_PATH, output_apk), "sign", env=env)
    except StageError as exc:
        message = exc.details.lower()
        if "keystore was tampered with" in message or "password was incorrect" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    "Подписывающая утилита не смогла открыть keystore.",
                    details=exc.details,
                )
            ) from exc
        if "does not exist" in message and "alias" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    f"В keystore '{KS_PATH}' не найден alias '{KS_ALIAS}'.",
                    details=exc.details,
                )
            ) from exc
        if "cannot recover key" in message or "failed to obtain key" in message:
            raise KeystoreConfigError(
                format_keystore_error(
                    "Keystore открылся, но пароль ключа внутри него не подошел. Проверьте KS_KEY_PASS.",
                    details=exc.details,
                )
            ) from exc
        raise

    if VERIFY_SIGNED_APK:
        run_command(build_apksigner_verify_command(output_apk), "verify", env=env)


def patch_apk(input_path, new_package):
    work_dir = TEMP_WORK_DIR
    java_env = {**os.environ, "JAVA_OPTS": JAVA_OPTS}

    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)

    for artifact in (UNSIGNED_APK_PATH, ALIGNED_APK_PATH, OUTPUT_APK_PATH):
        remove_file_if_exists(artifact)

    print("📦 Распаковка (может занять несколько минут для больших APK)...")
    run_command(
        ["apktool", "d", input_path, "-o", work_dir, "-f"],
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

    print("🔨 Сборка...")
    run_command(
        ["apktool", "b", work_dir, "-o", UNSIGNED_APK_PATH],
        "build",
        env=java_env,
    )

    print("📏 Zipalign...")
    print("✍️ Подпись (V2/V3)...")
    sign_apk(UNSIGNED_APK_PATH, OUTPUT_APK_PATH, env=java_env)

    return OUTPUT_APK_PATH


def _legacy_build_stage_message(error):
    if error.stage == "decode":
        return (
            "❌ Не удалось распаковать APK через apktool.\n\n"
            f"{error.details or 'Проверьте, что файл не поврежден и не защищен от разборки.'}"
        )
    if error.stage == "build":
        return (
            "❌ Не удалось собрать APK после изменений.\n\n"
            f"{error.details or 'Проверьте smali/manifest после модификации.'}"
        )
    if error.stage == "zipalign":
        return (
            "❌ Не удалось выровнять APK через zipalign.\n\n"
            f"{error.details or 'Проверьте, что zipalign установлен и доступен в PATH.'}"
        )
    if error.stage == "sign":
        return (
            "❌ Не удалось подписать APK.\n\n"
            f"{error.details or 'Проверьте keystore и параметры подписи.'}"
        )
    return f"❌ Ошибка на этапе '{error.stage}'.\n\n{error.details or 'Без деталей.'}"


    if error.stage == "verify":
        return (
            "вќЊ РџРѕРґРїРёСЃР°РЅРЅС‹Р№ APK РЅРµ РїСЂРѕС€РµР» РїСЂРѕРІРµСЂРєСѓ apksigner.\n\n"
            f"{error.details or 'РџСЂРѕРІРµСЂСЊС‚Рµ SIGN_V1_ENABLED, SIGN_V2_ENABLED, SIGN_V3_ENABLED Рё SIGN_MIN_SDK_VERSION.'}"
        )


def build_stage_message(error):
    if error.stage == "decode":
        return (
            "❌ Не удалось распаковать APK через apktool.\n\n"
            f"{error.details or 'Проверьте, что файл не повреждён и может быть обработан apktool.'}"
        )
    if error.stage == "build":
        return (
            "❌ Не удалось пересобрать APK.\n\n"
            f"{error.details or 'Проверьте изменения smali и манифеста после патчинга.'}"
        )
    if error.stage == "zipalign":
        return (
            "❌ Не удалось выровнять APK через zipalign.\n\n"
            f"{error.details or 'Проверьте, что zipalign установлен и доступен в PATH.'}"
        )
    if error.stage == "sign":
        return (
            "❌ Не удалось подписать APK.\n\n"
            f"{error.details or 'Проверьте конфигурацию keystore и параметры подписи.'}"
        )
    if error.stage == "verify":
        return (
            "❌ Подписанный APK не прошёл проверку apksigner.\n\n"
            f"{error.details or 'Проверьте SIGN_V1_ENABLED, SIGN_V2_ENABLED, SIGN_V3_ENABLED и SIGN_MIN_SDK_VERSION.'}"
        )
    return f"❌ Ошибка на этапе '{error.stage}'.\n\n{error.details or 'Без деталей.'}"


@dp.message(F.document)
async def handle_apk(message: types.Message):
    if not message.document.file_name.endswith(".apk"):
        return await message.answer("⚠️ Пришли файл формата .apk")

    await message.answer(
        "🚀 Начинаю реверс, инъекцию защиты и пересборку. Ожидайте..."
    )

    file_id = message.document.file_id
    input_name = os.path.basename(message.document.file_name)
    input_file = os.path.join(DOWNLOADS_DIR, input_name)
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)

    file = await message.bot.get_file(file_id)
    await message.bot.download_file(file.file_path, input_file)

    try:
        new_pkg = choose_random_package()
        result_path = await asyncio.to_thread(patch_apk, input_file, new_pkg)
        result_sha256 = await asyncio.to_thread(calculate_sha256, result_path)
        await message.answer_document(
            FSInputFile(result_path, filename=input_name),
            caption=(
                f"SHA-256: {result_sha256}\n"
                "✅ Готово!\n\n"
                "🛡 Внедрен анти-дебаг\n"
                "🧬 Код мутирован (изменен DEX хеш)\n"
                f"📦 Новый пакет: {new_pkg}"
            ),
        )
    except KeystoreConfigError as exc:
        await message.answer(f"❌ Ошибка keystore:\n\n{exc}")
    except StageError as exc:
        await message.answer(build_stage_message(exc))
    except Exception as exc:
        await message.answer(f"❌ Системная ошибка: {exc}")
    finally:
        if os.path.exists(TEMP_WORK_DIR):
            shutil.rmtree(TEMP_WORK_DIR)
        if os.path.exists(input_file):
            os.remove(input_file)
        remove_file_if_exists(UNSIGNED_APK_PATH)
        remove_file_if_exists(ALIGNED_APK_PATH)


async def main():
    errors = []

    if not API_TOKEN:
        errors.append(
            "[ТОКЕН]   Переменная BOT_TOKEN не задана.\n"
            "          -> Windows:   set BOT_TOKEN=ваш_токен\n"
            "          -> Linux/Mac: export BOT_TOKEN=ваш_токен"
        )

    checks = [
        (
            SIGNER_PATH,
            "Скачайте uber-apk-signer:\n"
            "          -> https://github.com/patrickfav/uber-apk-signer/releases\n"
            "          -> Положите .jar рядом с main.py или задайте SIGNER_PATH",
        ),
        (
            KS_PATH,
            "Создайте keystore или укажите путь через KS_PATH:\n"
            "          -> keytool -genkey -v -keystore my-release-key.jks "
            "-alias my-alias -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 10000 "
            "-storepass 12345678 -keypass 12345678",
        ),
    ]
    for fpath, hint in checks:
        if not os.path.exists(fpath):
            errors.append(f"[ФАЙЛ]    '{fpath}' не найден.\n          {hint}")

    tools = [
        ("java", "Установите JDK/JRE и добавьте в PATH."),
        (
            "apktool",
            "Установите apktool:\n"
            "          -> https://apktool.org/docs/install\n"
            "          -> Убедитесь, что 'apktool' доступен из командной строки.",
        ),
        (
            ZIPALIGN_PATH,
            "Установите zipalign и добавьте его в PATH либо задайте ZIPALIGN_PATH.",
        ),
    ]
    for tool, hint in tools:
        if not shutil.which(tool) and not os.path.exists(tool):
            errors.append(f"[PATH]    '{tool}' не найден.\n          {hint}")

    if not errors:
        try:
            validate_keystore()
        except KeystoreConfigError as exc:
            errors.append(
                "[KEYSTORE] Неверная конфигурация подписи.\n"
                f"          {exc}\n"
                "          -> Проверьте KS_PATH, KS_ALIAS, KS_PASS, KS_KEY_PASS, KS_TYPE и KS_PASS_ENCODING."
            )

    if errors:
        print("=" * 60)
        print("  ПРЕДСТАРТОВАЯ ПРОВЕРКА: обнаружены проблемы")
        print("=" * 60)
        for index, err in enumerate(errors, 1):
            print(f"\n  {index}. {err}")
        print("\n" + "=" * 60)
        print("  Устраните проблемы выше и перезапустите скрипт.")
        print("=" * 60)
        return

    bot = Bot(token=API_TOKEN)
    print("Бот-Аналитик запущен!")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
