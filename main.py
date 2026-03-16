# -*- coding: utf-8 -*-
import asyncio
import os
import random
import re
import shutil
import string
import subprocess

from aiogram import Bot, Dispatcher, F, types
from aiogram.types import FSInputFile
from dotenv import load_dotenv

load_dotenv()

# --- Настройки ---
API_TOKEN = os.getenv("BOT_TOKEN", "").strip()
SIGNER_PATH = os.getenv("SIGNER_PATH", "uber-apk-signer-1.3.0.jar")
KS_PATH = os.getenv("KS_PATH", "my-release-key.jks")
KS_ALIAS = os.getenv("KS_ALIAS", "my-alias")
KS_PASS = os.getenv("KS_PASS", "12345678")
KS_KEY_PASS = os.getenv("KS_KEY_PASS", KS_PASS)
JAVA_OPTS = os.getenv("JAVA_OPTS", "-Xmx256m")

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


def normalize_cli_output(text, limit=1200):
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


def validate_keystore():
    if not os.path.exists(KS_PATH):
        return

    keytool_path = shutil.which("keytool")
    if not keytool_path:
        return

    try:
        run_command(
            [
                keytool_path,
                "-list",
                "-keystore",
                KS_PATH,
                "-alias",
                KS_ALIAS,
                "-storepass",
                KS_PASS,
            ],
            "keystore-check",
        )
    except StageError as exc:
        message = exc.details.lower()
        if "password was incorrect" in message or "keystore was tampered with" in message:
            raise KeystoreConfigError(
                "Не удалось открыть keystore. Проверьте KS_PASS и сам файл "
                f"'{KS_PATH}'."
            ) from exc
        if "alias <" in message and "does not exist" in message:
            raise KeystoreConfigError(
                f"В keystore '{KS_PATH}' не найден alias '{KS_ALIAS}'."
            ) from exc
        raise KeystoreConfigError(
            "Не удалось проверить keystore. "
            f"Подробности: {exc.details or 'неизвестная ошибка'}"
        ) from exc


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

        smali_content = f"""
.class public Lcom/security/guard/{class_name};
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static {method_name}()I
    .registers 2
    const/4 v0, 0x1
    const/4 v1, 0x0
    add-int/2addr v0, v1
    return v0
.end method
"""
        smali_file = os.path.join(fake_package_path, f"{class_name}.smali")
        with open(smali_file, "w", encoding="utf-8") as file:
            file.write(smali_content)


def sign_apk(output_apk):
    try:
        run_command(
            [
                "java",
                "-jar",
                SIGNER_PATH,
                "--apks",
                output_apk,
                "--ks",
                KS_PATH,
                "--ksAlias",
                KS_ALIAS,
                "--ksPass",
                f"pass:{KS_PASS}",
                "--ksKeyPass",
                f"pass:{KS_KEY_PASS}",
                "--allowResign",
                "--overwrite",
            ],
            "sign",
        )
    except StageError as exc:
        message = exc.details.lower()
        if "password verification failed" in message or "keystore was tampered with" in message:
            raise KeystoreConfigError(
                "Пароль keystore неверный. Укажите правильный KS_PASS "
                f"для файла '{KS_PATH}'."
            ) from exc
        if "alias" in message and "does not exist" in message:
            raise KeystoreConfigError(
                f"В keystore '{KS_PATH}' не найден alias '{KS_ALIAS}'."
            ) from exc
        if "cannot recover key" in message or "failed to obtain key" in message:
            raise KeystoreConfigError(
                "Пароль ключа неверный. Проверьте KS_KEY_PASS."
            ) from exc
        raise


def patch_apk(input_path, new_package):
    work_dir = "temp_work"
    output_apk = "rebuilt_game.apk"
    java_env = {**os.environ, "JAVA_OPTS": JAVA_OPTS}

    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)

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
        ["apktool", "b", work_dir, "-o", output_apk],
        "build",
        env=java_env,
    )

    print("✍️ Подпись (V2/V3)...")
    sign_apk(output_apk)

    return output_apk


def build_stage_message(error):
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
    if error.stage == "sign":
        return (
            "❌ Не удалось подписать APK.\n\n"
            f"{error.details or 'Проверьте keystore и параметры подписи.'}"
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
    input_file = f"downloads/{message.document.file_name}"
    os.makedirs("downloads", exist_ok=True)

    file = await message.bot.get_file(file_id)
    await message.bot.download_file(file.file_path, input_file)

    try:
        new_pkg = f"com.secured.{generate_random_string(5).lower()}"
        result_path = await asyncio.to_thread(patch_apk, input_file, new_pkg)
        await message.answer_document(
            FSInputFile(result_path),
            caption=(
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
        if os.path.exists("temp_work"):
            shutil.rmtree("temp_work")
        if os.path.exists(input_file):
            os.remove(input_file)


async def main():
    errors = []

    if not API_TOKEN:
        errors.append(
            "[ТОКЕН]   Переменная BOT_TOKEN не задана.\n"
            "          → Windows:   set BOT_TOKEN=ваш_токен\n"
            "          → Linux/Mac: export BOT_TOKEN=ваш_токен"
        )

    checks = [
        (
            SIGNER_PATH,
            "Скачайте uber-apk-signer:\n"
            "          → https://github.com/patrickfav/uber-apk-signer/releases\n"
            "          → Положите .jar рядом с main.py или задайте SIGNER_PATH",
        ),
        (
            KS_PATH,
            "Создайте keystore или укажите путь через KS_PATH:\n"
            "          → keytool -genkey -v -keystore my-release-key.jks "
            "-alias my-alias -keyalg RSA -keysize 2048 -validity 10000 "
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
            "          → https://apktool.org/docs/install\n"
            "          → Убедитесь, что 'apktool' доступен из командной строки.",
        ),
    ]
    for tool, hint in tools:
        if not shutil.which(tool):
            errors.append(f"[PATH]    '{tool}' не найден в PATH.\n          {hint}")

    if not errors:
        try:
            validate_keystore()
        except KeystoreConfigError as exc:
            errors.append(
                "[KEYSTORE] Неверная конфигурация подписи.\n"
                f"          {exc}\n"
                "          → Проверьте KS_PATH, KS_ALIAS, KS_PASS и KS_KEY_PASS."
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
