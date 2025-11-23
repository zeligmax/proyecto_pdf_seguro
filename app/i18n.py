#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de internacionalización para File Secure v3.1
Gestiona las traducciones y cambio de idioma dinámico
"""

import json
from pathlib import Path
from typing import Dict, Optional

class Translator:
    """
    Gestor de traducciones multi-idioma
    Carga archivos JSON organizados por categoría
    """

    def __init__(self, language: str = 'es'):
        """
        Inicializa el traductor

        Args:
            language: Código de idioma ('es' o 'en')
        """
        self.language = language
        self.locales_path = Path(__file__).parent.parent / 'locales'
        self.translations: Dict[str, Dict[str, str]] = {}
        self.load_translations()

    def load_translations(self) -> None:
        """Carga todas las traducciones del idioma actual"""
        lang_path = self.locales_path / self.language

        if not lang_path.exists():
            print(f"⚠️ Advertencia: No existe el directorio de idioma '{self.language}'")
            return

        # Archivos de traducción por categoría
        translation_files = ['common.json', 'gui.json', 'cli.json', 'errors.json']

        for file in translation_files:
            file_path = lang_path / file
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        category = file.replace('.json', '')
                        self.translations[category] = json.load(f)
                except Exception as e:
                    print(f"⚠️ Error cargando {file_path}: {e}")
            else:
                # Crear diccionario vacío si no existe el archivo
                category = file.replace('.json', '')
                self.translations[category] = {}

    def get(self, key: str, category: str = 'common', **kwargs) -> str:
        """
        Obtiene una traducción por clave

        Args:
            key: Clave de traducción
            category: Categoría (common, gui, cli, errors)
            **kwargs: Variables para interpolación

        Returns:
            Texto traducido, o la clave si no se encuentra
        """
        text = self.translations.get(category, {}).get(key, key)

        # Interpolación de variables
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError as e:
                print(f"⚠️ Variable no encontrada en traducción '{key}': {e}")

        return text

    def change_language(self, language: str) -> None:
        """
        Cambia el idioma y recarga traducciones

        Args:
            language: Nuevo código de idioma
        """
        self.language = language
        self.translations.clear()
        self.load_translations()

    def get_available_languages(self) -> list:
        """Retorna lista de idiomas disponibles"""
        if not self.locales_path.exists():
            return ['es']

        languages = []
        for item in self.locales_path.iterdir():
            if item.is_dir():
                languages.append(item.name)

        return sorted(languages) if languages else ['es']


# Instancia global del traductor (Singleton)
_translator: Optional[Translator] = None


def init_translator(language: str = 'es') -> Translator:
    """
    Inicializa el traductor global

    Args:
        language: Idioma inicial

    Returns:
        Instancia del traductor
    """
    global _translator
    _translator = Translator(language)
    return _translator


def get_translator() -> Translator:
    """
    Obtiene la instancia global del traductor

    Returns:
        Instancia del traductor (crea una nueva si no existe)
    """
    global _translator
    if _translator is None:
        _translator = Translator()
    return _translator


def t(key: str, category: str = 'common', **kwargs) -> str:
    """
    Atajo para traducir texto

    Args:
        key: Clave de traducción
        category: Categoría de traducción
        **kwargs: Variables para interpolación

    Returns:
        Texto traducido

    Ejemplos:
        t('app_title')  # Traducción simple
        t('welcome_user', username='Juan')  # Con variables
        t('button_encrypt', category='gui')  # Categoría específica
    """
    return get_translator().get(key, category, **kwargs)


def change_language(language: str) -> None:
    """
    Cambia el idioma global de la aplicación

    Args:
        language: Código del nuevo idioma
    """
    get_translator().change_language(language)


def get_current_language() -> str:
    """
    Obtiene el idioma actual

    Returns:
        Código del idioma actual
    """
    return get_translator().language
