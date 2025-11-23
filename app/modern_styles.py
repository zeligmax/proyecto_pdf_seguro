#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modern Styles Module - File Secure v3.1
Estilos modernos con paleta de colores pastel inspirados en SAP
"""

import tkinter as tk
from tkinter import ttk

class ModernTheme:
    """
    Tema moderno con colores pastel para File Secure v3.1
    Inspirado en diseños tipo SAP con colores suaves y profesionales
    """

    # Paleta de colores pastel moderna
    COLORS = {
        # Colores principales pastel
        'pastel_green': '#A8E6CF',      # Verde pastel suave
        'pastel_pink': '#FFB3BA',       # Rosa pastel
        'pastel_yellow': '#FFFFBA',     # Amarillo pastel
        'pastel_blue': '#BAE1FF',       # Azul pastel
        'pastel_purple': '#E0BBE4',     # Púrpura pastel
        'pastel_orange': '#FFD8B8',     # Naranja pastel

        # Fondos y neutros
        'bg_main': '#F5F7FA',           # Fondo principal gris muy claro
        'bg_white': '#FFFFFF',          # Blanco puro
        'bg_card': '#FFFFFF',           # Fondo de tarjetas
        'bg_hover': '#E8F4F8',          # Hover azul muy claro

        # Textos
        'text_primary': '#2C3E50',      # Texto principal oscuro
        'text_secondary': '#7F8C8D',    # Texto secundario gris
        'text_light': '#95A5A6',        # Texto claro
        'text_white': '#FFFFFF',        # Texto blanco

        # Bordes y líneas
        'border_light': '#E1E8ED',      # Borde claro
        'border_medium': '#CBD5E0',     # Borde medio
        'border_dark': '#A0AEC0',       # Borde oscuro

        # Estados
        'success': '#6BCF7F',           # Verde éxito
        'error': '#FF6B6B',             # Rojo error
        'warning': '#FFA726',           # Naranja advertencia
        'info': '#42A5F5',              # Azul info

        # Sombras
        'shadow': '#00000015',          # Sombra suave
        'shadow_strong': '#00000030',   # Sombra fuerte
    }

    # Fuentes modernas
    FONTS = {
        'title': ('Segoe UI', 16, 'bold'),
        'subtitle': ('Segoe UI', 13, 'bold'),
        'heading': ('Segoe UI', 11, 'bold'),
        'body': ('Segoe UI', 10),
        'small': ('Segoe UI', 9),
        'code': ('Consolas', 10),
    }

    # Espaciado (padding)
    SPACING = {
        'xs': 5,
        'sm': 10,
        'md': 15,
        'lg': 20,
        'xl': 30,
    }

    @staticmethod
    def configure_style(root):
        """
        Configura el estilo moderno para toda la aplicación

        Args:
            root: Ventana principal Tk
        """
        style = ttk.Style(root)

        # Configurar tema base
        try:
            style.theme_use('clam')  # Tema base más personalizable
        except:
            pass

        # ===== CONFIGURACIÓN GENERAL =====

        # Fondo principal
        root.configure(bg=ModernTheme.COLORS['bg_main'])

        # ===== FRAMES =====

        style.configure('TFrame',
            background=ModernTheme.COLORS['bg_main'],
            borderwidth=0
        )

        # Frame tipo tarjeta (elevado)
        style.configure('Card.TFrame',
            background=ModernTheme.COLORS['bg_card'],
            relief='flat',
            borderwidth=1
        )

        # ===== LABELS =====

        style.configure('TLabel',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['body']
        )

        # Label de título
        style.configure('Title.TLabel',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['title']
        )

        # Label de subtítulo
        style.configure('Subtitle.TLabel',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_secondary'],
            font=ModernTheme.FONTS['subtitle']
        )

        # Label de encabezado
        style.configure('Heading.TLabel',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        # ===== LABELFRAMES =====

        style.configure('TLabelframe',
            background=ModernTheme.COLORS['bg_card'],
            borderwidth=2,
            relief='solid',
            bordercolor=ModernTheme.COLORS['border_light']
        )

        style.configure('TLabelframe.Label',
            background=ModernTheme.COLORS['bg_card'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        # LabelFrames con colores pastel
        style.configure('Green.TLabelframe',
            background=ModernTheme.COLORS['pastel_green'],
            borderwidth=2,
            relief='solid',
            bordercolor=ModernTheme.COLORS['success']
        )

        style.configure('Green.TLabelframe.Label',
            background=ModernTheme.COLORS['pastel_green'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        style.configure('Pink.TLabelframe',
            background=ModernTheme.COLORS['pastel_pink'],
            borderwidth=2,
            relief='solid',
            bordercolor='#FF8A95'
        )

        style.configure('Pink.TLabelframe.Label',
            background=ModernTheme.COLORS['pastel_pink'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        style.configure('Yellow.TLabelframe',
            background=ModernTheme.COLORS['pastel_yellow'],
            borderwidth=2,
            relief='solid',
            bordercolor='#FFE680'
        )

        style.configure('Yellow.TLabelframe.Label',
            background=ModernTheme.COLORS['pastel_yellow'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        style.configure('Blue.TLabelframe',
            background=ModernTheme.COLORS['pastel_blue'],
            borderwidth=2,
            relief='solid',
            bordercolor='#89CFF0'
        )

        style.configure('Blue.TLabelframe.Label',
            background=ModernTheme.COLORS['pastel_blue'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['heading']
        )

        # ===== BUTTONS =====

        # Botón principal (verde)
        style.configure('Primary.TButton',
            font=ModernTheme.FONTS['body'],
            borderwidth=0,
            relief='flat',
            padding=(15, 8),
            background=ModernTheme.COLORS['success'],
            foreground=ModernTheme.COLORS['text_white']
        )

        style.map('Primary.TButton',
            background=[('active', '#5CB370'), ('pressed', '#4DA661')],
            relief=[('pressed', 'flat')]
        )

        # Botón secundario (azul)
        style.configure('Secondary.TButton',
            font=ModernTheme.FONTS['body'],
            borderwidth=0,
            relief='flat',
            padding=(15, 8),
            background=ModernTheme.COLORS['info'],
            foreground=ModernTheme.COLORS['text_white']
        )

        style.map('Secondary.TButton',
            background=[('active', '#3895E5'), ('pressed', '#2E85D5')],
            relief=[('pressed', 'flat')]
        )

        # Botón de peligro (rojo)
        style.configure('Danger.TButton',
            font=ModernTheme.FONTS['body'],
            borderwidth=0,
            relief='flat',
            padding=(15, 8),
            background=ModernTheme.COLORS['error'],
            foreground=ModernTheme.COLORS['text_white']
        )

        style.map('Danger.TButton',
            background=[('active', '#E55B5B'), ('pressed', '#D54B4B')],
            relief=[('pressed', 'flat')]
        )

        # Botón de advertencia (naranja)
        style.configure('Warning.TButton',
            font=ModernTheme.FONTS['body'],
            borderwidth=0,
            relief='flat',
            padding=(15, 8),
            background=ModernTheme.COLORS['warning'],
            foreground=ModernTheme.COLORS['text_white']
        )

        style.map('Warning.TButton',
            background=[('active', '#F09716'), ('pressed', '#E08706')],
            relief=[('pressed', 'flat')]
        )

        # Botón estándar mejorado
        style.configure('TButton',
            font=ModernTheme.FONTS['body'],
            borderwidth=1,
            relief='flat',
            padding=(12, 6),
            background=ModernTheme.COLORS['bg_card'],
            foreground=ModernTheme.COLORS['text_primary'],
            bordercolor=ModernTheme.COLORS['border_medium']
        )

        style.map('TButton',
            background=[('active', ModernTheme.COLORS['bg_hover']), ('pressed', ModernTheme.COLORS['border_light'])],
            bordercolor=[('active', ModernTheme.COLORS['info'])]
        )

        # ===== ENTRY =====

        style.configure('TEntry',
            fieldbackground=ModernTheme.COLORS['bg_white'],
            foreground=ModernTheme.COLORS['text_primary'],
            borderwidth=2,
            relief='solid',
            bordercolor=ModernTheme.COLORS['border_light'],
            padding=8,
            font=ModernTheme.FONTS['body']
        )

        style.map('TEntry',
            bordercolor=[('focus', ModernTheme.COLORS['info'])]
        )

        # ===== COMBOBOX =====

        style.configure('TCombobox',
            fieldbackground=ModernTheme.COLORS['bg_white'],
            background=ModernTheme.COLORS['bg_white'],
            foreground=ModernTheme.COLORS['text_primary'],
            borderwidth=2,
            relief='solid',
            bordercolor=ModernTheme.COLORS['border_light'],
            arrowcolor=ModernTheme.COLORS['text_secondary'],
            padding=8,
            font=ModernTheme.FONTS['body']
        )

        style.map('TCombobox',
            fieldbackground=[('readonly', ModernTheme.COLORS['bg_white'])],
            bordercolor=[('focus', ModernTheme.COLORS['info'])]
        )

        # ===== NOTEBOOK (PESTAÑAS) =====

        style.configure('TNotebook',
            background=ModernTheme.COLORS['bg_main'],
            borderwidth=0,
            tabmargins=[2, 5, 2, 0]
        )

        style.configure('TNotebook.Tab',
            background=ModernTheme.COLORS['border_light'],
            foreground=ModernTheme.COLORS['text_secondary'],
            padding=[20, 10],
            font=ModernTheme.FONTS['body'],
            borderwidth=0
        )

        style.map('TNotebook.Tab',
            background=[('selected', ModernTheme.COLORS['bg_card'])],
            foreground=[('selected', ModernTheme.COLORS['text_primary'])],
            expand=[('selected', [1, 1, 1, 0])]
        )

        # ===== TREEVIEW =====

        style.configure('Treeview',
            background=ModernTheme.COLORS['bg_white'],
            foreground=ModernTheme.COLORS['text_primary'],
            fieldbackground=ModernTheme.COLORS['bg_white'],
            borderwidth=1,
            relief='solid',
            rowheight=28,
            font=ModernTheme.FONTS['body']
        )

        style.configure('Treeview.Heading',
            background=ModernTheme.COLORS['pastel_blue'],
            foreground=ModernTheme.COLORS['text_primary'],
            relief='flat',
            borderwidth=1,
            font=ModernTheme.FONTS['heading']
        )

        style.map('Treeview',
            background=[('selected', ModernTheme.COLORS['info'])],
            foreground=[('selected', ModernTheme.COLORS['text_white'])]
        )

        # ===== CHECKBUTTON =====

        style.configure('TCheckbutton',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['body']
        )

        # ===== RADIOBUTTON =====

        style.configure('TRadiobutton',
            background=ModernTheme.COLORS['bg_main'],
            foreground=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['body']
        )

        # ===== SCROLLBAR =====

        style.configure('TScrollbar',
            background=ModernTheme.COLORS['border_medium'],
            troughcolor=ModernTheme.COLORS['bg_main'],
            borderwidth=0,
            arrowcolor=ModernTheme.COLORS['text_primary']
        )

        # ===== PROGRESSBAR =====

        style.configure('TProgressbar',
            background=ModernTheme.COLORS['success'],
            troughcolor=ModernTheme.COLORS['border_light'],
            borderwidth=0,
            thickness=20
        )

    @staticmethod
    def create_card_frame(parent, **kwargs):
        """
        Crea un frame estilo tarjeta con sombra visual

        Args:
            parent: Widget padre
            **kwargs: Argumentos adicionales para el Frame

        Returns:
            Frame configurado como tarjeta
        """
        # Frame exterior con padding para simular sombra
        outer = ttk.Frame(parent, style='TFrame')

        # Frame interior (la tarjeta)
        card = ttk.Frame(outer, style='Card.TFrame', **kwargs)
        card.pack(padx=2, pady=2, fill=tk.BOTH, expand=True)

        return outer, card

    @staticmethod
    def create_gradient_header(parent, text, color='pastel_blue'):
        """
        Crea un encabezado con fondo de color pastel

        Args:
            parent: Widget padre
            text: Texto del encabezado
            color: Color de fondo (clave en COLORS)

        Returns:
            Frame del encabezado
        """
        header = tk.Frame(parent, bg=ModernTheme.COLORS.get(color, ModernTheme.COLORS['pastel_blue']), height=60)
        header.pack(fill=tk.X, pady=(0, 15))
        header.pack_propagate(False)

        label = tk.Label(
            header,
            text=text,
            bg=ModernTheme.COLORS.get(color, ModernTheme.COLORS['pastel_blue']),
            fg=ModernTheme.COLORS['text_primary'],
            font=ModernTheme.FONTS['title']
        )
        label.pack(expand=True)

        return header

    @staticmethod
    def create_modern_button(parent, text, command=None, style='Primary', **kwargs):
        """
        Crea un botón moderno con estilo específico

        Args:
            parent: Widget padre
            text: Texto del botón
            command: Función a ejecutar al hacer clic
            style: Estilo del botón (Primary, Secondary, Danger, Warning)
            **kwargs: Argumentos adicionales

        Returns:
            Botón configurado
        """
        btn = ttk.Button(parent, text=text, command=command, style=f'{style}.TButton', **kwargs)
        return btn
