# -*- coding: utf-8 -*-
import os
import subprocess
import asyncio
import shutil
import random
import re
import string
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, types
from aiogram.types import FSInputFile

load_dotenv()

# --- НАСТРОЙКИ ---
API_TOKEN = os.getenv('BOT_TOKEN', '')
SIGNER_PATH = 'uber-apk-signer-1.3.0.jar'      
KS_PATH = 'my-release-key.jks'  
KS_ALIAS = 'my-alias'           
KS_PASS = '12345678'            

dp = Dispatcher()

def generate_random_string(length=10):
    """Генерирует случайную строку для названий фейковых классов"""
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def inject_security_measures(work_dir):
    """Модуль Харденинга и Мутации кода"""
    print("🔒 Применение защиты кода...")
    
    # 1. Manifest Hardening (Защита от дебаггера и бекапов)
    manifest = os.path.join(work_dir, "AndroidManifest.xml")
    if os.path.exists(manifest):
        with open(manifest, "r", encoding="utf-8") as f:
            data = f.read()
        
        # Принудительно отключаем дебаг и бекапы в теге <application>
        data = re.sub(r'android:debuggable="(true|false)"', '', data)
        data = re.sub(r'android:allowBackup="(true|false)"', '', data)
        
        # Вставляем наши строгие правила
        data = data.replace('<application', '<application android:debuggable="false" android:allowBackup="false"')
        
        with open(manifest, "w", encoding="utf-8") as f:
            f.write(data)

    # 2. Smali Mutation (Инъекция мусорного кода для изменения хеша и запутывания)
    # Создаем фейковую директорию внутри исходников
    fake_package_path = os.path.join(work_dir, "smali", "com", "security", "guard")
    os.makedirs(fake_package_path, exist_ok=True)
    
    # Генерируем 5 случайных мусорных классов
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
        with open(os.path.join(fake_package_path, f"{class_name}.smali"), "w", encoding="utf-8") as f:
            f.write(smali_content)


def patch_apk(input_path, new_package):
    work_dir = "temp_work"
    output_apk = "rebuilt_game.apk"
    
    if os.path.exists(work_dir): shutil.rmtree(work_dir)
    
    print("📦 Распаковка (может занять несколько минут для больших APK)...")
    subprocess.run(["apktool", "d", input_path, "-o", work_dir, "-f"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={**os.environ, "JAVA_OPTS": "-Xmx256m"})
    
    # Замена Package Name
    manifest = os.path.join(work_dir, "AndroidManifest.xml")
    with open(manifest, "r", encoding="utf-8") as f:
        data = f.read()
    data = re.sub(r'package="[^"]+"', f'package="{new_package}"', data)
    with open(manifest, "w", encoding="utf-8") as f:
        f.write(data)

    # --- ВЫЗОВ НАШЕЙ ЗАЩИТЫ ---
    inject_security_measures(work_dir)

    print("🔨 Сборка...")
    subprocess.run(["apktool", "b", work_dir, "-o", output_apk],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={**os.environ, "JAVA_OPTS": "-Xmx256m"})

    print("✍️ Подпись (V2/V3)...")
    subprocess.run([
        "java", "-jar", SIGNER_PATH,
        "--apks", output_apk,
        "--ks", KS_PATH,
        "--ksAlias", KS_ALIAS,
        "--ksPass", f"pass:{KS_PASS}",
        "--ksKeyPass", f"pass:{KS_PASS}",
        "--allowResign",
        "--overwrite"
    ], check=True)

    return output_apk

@dp.message(F.document)
async def handle_apk(message: types.Message):
    if not message.document.file_name.endswith(".apk"):
        return await message.answer("⚠️ Пришли файл формата .apk")

    await message.answer("🚀 Начинаю реверс, инъекцию защиты и пересборку. Ожидайте...")
    
    file_id = message.document.file_id
    input_file = f"downloads/{message.document.file_name}"
    os.makedirs("downloads", exist_ok=True)
    
    file = await message.bot.get_file(file_id)
    await message.bot.download_file(file.file_path, input_file)
    try:
        new_pkg = f"com.secured.{generate_random_string(5).lower()}" # Генерируем уникальный пакет
        result_path = await asyncio.to_thread(patch_apk, input_file, new_pkg)
        
        await message.answer_document(FSInputFile(result_path), caption=f"✅ Готово!\n\n🛡 Внедрен анти-дебаг\n🧬 Код мутирован (изменен DEX хеш)\n📦 Новый пакет: {new_pkg}")
    except subprocess.CalledProcessError as e:
         await message.answer(f"❌ Ошибка компиляции Apktool. Возможно, файл защищен от разборки.")
    except Exception as e:
        await message.answer(f"❌ Системная ошибка: {str(e)}")
    finally:
        if os.path.exists("temp_work"): shutil.rmtree("temp_work")
        if os.path.exists(input_file): os.remove(input_file)

async def main():
    errors = []

    # 1. Токен
    if not API_TOKEN:
        errors.append("[ТОКЕН]   Переменная BOT_TOKEN не задана.\n"
                       "          → Windows:   set BOT_TOKEN=ваш_токен\n"
                       "          → Linux/Mac: export BOT_TOKEN=ваш_токен")

    # 2. Обязательные файлы
    checks = [
        (SIGNER_PATH,
         "Скачайте uber-apk-signer:\n"
         "          → https://github.com/patrickfav/uber-apk-signer/releases\n"
         "          → Переименуйте .jar в signer.jar и положите рядом с main.py"),
        (KS_PATH,
         "Создайте keystore:\n"
         "          → keytool -genkey -v -keystore my-release-key.jks "
         "-alias my-alias -keyalg RSA -keysize 2048 -validity 10000 "
         "-storepass 12345678 -keypass 12345678"),
    ]
    for fpath, hint in checks:
        if not os.path.exists(fpath):
            errors.append(f"[ФАЙЛ]    '{fpath}' не найден.\n          {hint}")

    # 3. Внешние инструменты в PATH
    tools = [
        ('java',    "Установите JDK/JRE и добавьте в PATH."),
        ('apktool', "Установите apktool:\n"
                    "          → https://apktool.org/docs/install\n"
                    "          → Убедитесь, что 'apktool' доступен из командной строки."),
    ]
    for tool, hint in tools:
        if not shutil.which(tool):
            errors.append(f"[PATH]    '{tool}' не найден в PATH.\n          {hint}")

    # Итог
    if errors:
        print("=" * 60)
        print("  ПРЕДСТАРТОВАЯ ПРОВЕРКА: обнаружены проблемы")
        print("=" * 60)
        for i, err in enumerate(errors, 1):
            print(f"\n  {i}. {err}")
        print("\n" + "=" * 60)
        print("  Устраните проблемы выше и перезапустите скрипт.")
        print("=" * 60)
        return

    bot = Bot(token=API_TOKEN)
    print("Бот-Аналитик запущен!")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())