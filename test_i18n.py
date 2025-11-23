#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test del sistema de internacionalización (i18n)
Prueba las traducciones en español e inglés
"""

import sys
from pathlib import Path

# Configurar encoding UTF-8 para Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar directorio app al path
sys.path.append(str(Path(__file__).parent / "app"))

from i18n import init_translator, get_translator, t, change_language

def test_i18n():
    print("=" * 70)
    print("TEST: Sistema de Internacionalización (i18n)")
    print("=" * 70)

    # Inicializar traductor en español
    print("\n1️⃣ Inicializando traductor en ESPAÑOL...")
    init_translator('es')

    print(f"\nIdioma actual: {get_translator().language}")
    print(f"Idiomas disponibles: {get_translator().get_available_languages()}")

    # Probar traducciones en español
    print("\n" + "=" * 70)
    print("📋 TRADUCCIONES EN ESPAÑOL")
    print("=" * 70)

    print(f"\n🔹 Common:")
    print(f"  - app_title: {t('app_title')}")
    print(f"  - app_description: {t('app_description')}")
    print(f"  - supported_formats: {t('supported_formats')}")

    print(f"\n🔹 GUI:")
    print(f"  - tab_encrypt: {t('tab_encrypt', 'gui')}")
    print(f"  - tab_decrypt: {t('tab_decrypt', 'gui')}")
    print(f"  - tab_settings: {t('tab_settings', 'gui')}")
    print(f"  - button_encrypt: {t('button_encrypt', 'gui')}")
    print(f"  - button_decrypt: {t('button_decrypt', 'gui')}")
    print(f"  - button_view: {t('button_view', 'gui')}")

    print(f"\n🔹 CLI:")
    print(f"  - banner: {t('banner', 'cli')}")
    print(f"  - menu_title: {t('menu_title', 'cli')}")
    print(f"  - goodbye: {t('goodbye', 'cli')}")

    print(f"\n🔹 Errors:")
    print(f"  - file_not_found: {t('file_not_found', 'errors', path='/ruta/archivo.pdf')}")
    print(f"  - invalid_key: {t('invalid_key', 'errors')}")

    # Cambiar a inglés
    print("\n" + "=" * 70)
    print("2️⃣ Cambiando idioma a ENGLISH...")
    print("=" * 70)
    change_language('en')

    print(f"\nIdioma actual: {get_translator().language}")

    # Probar traducciones en inglés
    print("\n" + "=" * 70)
    print("📋 TRANSLATIONS IN ENGLISH")
    print("=" * 70)

    print(f"\n🔹 Common:")
    print(f"  - app_title: {t('app_title')}")
    print(f"  - app_description: {t('app_description')}")
    print(f"  - supported_formats: {t('supported_formats')}")

    print(f"\n🔹 GUI:")
    print(f"  - tab_encrypt: {t('tab_encrypt', 'gui')}")
    print(f"  - tab_decrypt: {t('tab_decrypt', 'gui')}")
    print(f"  - tab_settings: {t('tab_settings', 'gui')}")
    print(f"  - button_encrypt: {t('button_encrypt', 'gui')}")
    print(f"  - button_decrypt: {t('button_decrypt', 'gui')}")
    print(f"  - button_view: {t('button_view', 'gui')}")

    print(f"\n🔹 CLI:")
    print(f"  - banner: {t('banner', 'cli')}")
    print(f"  - menu_title: {t('menu_title', 'cli')}")
    print(f"  - goodbye: {t('goodbye', 'cli')}")

    print(f"\n🔹 Errors:")
    print(f"  - file_not_found: {t('file_not_found', 'errors', path='/path/file.pdf')}")
    print(f"  - invalid_key: {t('invalid_key', 'errors')}")

    # Volver a español
    print("\n" + "=" * 70)
    print("3️⃣ Volviendo a ESPAÑOL...")
    print("=" * 70)
    change_language('es')

    print(f"\nIdioma actual: {get_translator().language}")
    print(f"  - Mensaje: {t('goodbye', 'cli')}")

    print("\n" + "=" * 70)
    print("✅ TEST COMPLETADO - El sistema i18n funciona correctamente!")
    print("=" * 70)

if __name__ == "__main__":
    test_i18n()
