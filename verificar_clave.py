#!/usr/bin/env python3
"""
Verificador de Claves - Muestra exactamente qué pasa al descifrar
"""

import json
import sys
from pathlib import Path

def verificar_clave(archivo_enc, clave_usuario):
    """
    Verifica una clave contra un archivo cifrado
    Muestra EXACTAMENTE lo que está pasando
    """
    
    print("🔍 VERIFICACIÓN DETALLADA DE CLAVE")
    print("=" * 60)
    
    # Cargar archivo
    print(f"\n📄 Archivo: {Path(archivo_enc).name}")
    
    try:
        with open(archivo_enc, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error al cargar archivo: {e}")
        return
    
    print(f"✓ Archivo cargado correctamente")
    
    # Obtener claves del archivo
    user_keys_in_file = data.get('user_keys', {})
    
    print(f"\n👥 Usuarios autorizados en este archivo: {len(user_keys_in_file)}")
    print("-" * 60)
    
    # Mostrar cada usuario y su clave
    for i, (username, stored_key) in enumerate(user_keys_in_file.items(), 1):
        print(f"\n{i}. Usuario: '{username}'")
        print(f"   Longitud del nombre: {len(username)} caracteres")
        print(f"   Representación: {repr(username)}")  # Muestra espacios/caracteres ocultos
        print(f"   Clave almacenada: {stored_key[:30]}...")
        print(f"   Longitud clave: {len(stored_key)} caracteres")
    
    # Verificar la clave proporcionada
    print("\n" + "=" * 60)
    print("🔑 VERIFICACIÓN DE TU CLAVE")
    print("=" * 60)
    
    print(f"\nClave proporcionada: {clave_usuario[:30]}...")
    print(f"Longitud: {len(clave_usuario)} caracteres")
    print(f"Representación: {repr(clave_usuario)}")
    
    # Buscar coincidencia
    print("\n🔍 Buscando coincidencia...")
    print("-" * 60)
    
    encontrado = False
    for username, stored_key in user_keys_in_file.items():
        # Comparación byte a byte
        coincide = stored_key == clave_usuario
        
        print(f"\n📌 Comparando con usuario: '{username}'")
        print(f"   Clave archivo:  {stored_key[:40]}...")
        print(f"   Tu clave:       {clave_usuario[:40]}...")
        print(f"   ¿Coinciden?     {'✅ SÍ' if coincide else '❌ NO'}")
        
        if coincide:
            encontrado = True
            print(f"\n✅ ¡CLAVE VÁLIDA!")
            print(f"   Autorizado como usuario: {username}")
            break
        else:
            # Mostrar diferencias
            if len(stored_key) != len(clave_usuario):
                print(f"   ⚠️  Longitudes diferentes:")
                print(f"       Archivo: {len(stored_key)} caracteres")
                print(f"       Tuya:    {len(clave_usuario)} caracteres")
            else:
                # Encontrar primera diferencia
                for i, (c1, c2) in enumerate(zip(stored_key, clave_usuario)):
                    if c1 != c2:
                        print(f"   ⚠️  Primera diferencia en posición {i}:")
                        print(f"       Archivo: '{c1}' (ASCII {ord(c1)})")
                        print(f"       Tuya:    '{c2}' (ASCII {ord(c2)})")
                        break
    
    if not encontrado:
        print("\n" + "=" * 60)
        print("❌ CLAVE NO VÁLIDA PARA ESTE ARCHIVO")
        print("=" * 60)
        print("\n💡 Posibles causas:")
        print("1. La clave fue copiada incorrectamente")
        print("2. Hay espacios al inicio o final")
        print("3. Esta clave es para otro archivo")
        print("4. El archivo fue cifrado con otra clave maestra")
        
        print("\n🔧 Prueba esto:")
        print("1. Copia la clave de nuevo (sin espacios extra)")
        print("2. Verifica que sea para ESTE archivo específico")
        print("3. Usa Ctrl+A para seleccionar toda la clave")
    else:
        print("\n" + "=" * 60)
        print("✅ TODO CORRECTO - LA CLAVE DEBERÍA FUNCIONAR")
        print("=" * 60)
        
        print("\n🤔 Si aún así no descifra en la aplicación:")
        print("1. Puede ser un bug en el código de la GUI/CLI")
        print("2. Usa descifrar_manual.py como alternativa")
        print("3. Verifica que la clave maestra sea la misma")


def main():
    print("🔍 VERIFICADOR DE CLAVES - PDF SECURE v2.0\n")
    
    # Solicitar archivo
    print("📁 Archivo cifrado (.enc):")
    archivo = input("➡️  ").strip().strip('"').strip("'")
    
    if not archivo or not Path(archivo).exists():
        print("❌ Archivo no válido")
        return
    
    print("\n🔑 Clave de usuario:")
    clave = input("➡️  ").strip()
    
    if not clave:
        print("❌ No se proporcionó clave")
        return
    
    print()
    verificar_clave(archivo, clave)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Cancelado")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()