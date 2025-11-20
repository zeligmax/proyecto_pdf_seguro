#!/usr/bin/env python3
"""Test imports for PDF viewer"""

print("1. Testing fitz import...")
try:
    import fitz
    print(f"   OK - PyMuPDF version: {fitz.version}")
except ImportError as e:
    print(f"   FAIL - {e}")
except Exception as e:
    print(f"   ERROR - {e}")

print("\n2. Testing PIL imports...")
try:
    from PIL import Image, ImageTk
    print("   OK - Pillow imported successfully")
except ImportError as e:
    print(f"   FAIL - {e}")
except Exception as e:
    print(f"   ERROR - {e}")

print("\n3. Testing io...")
try:
    import io
    print("   OK - io module available")
except ImportError as e:
    print(f"   FAIL - {e}")

print("\n4. Testing tkinter...")
try:
    import tkinter as tk
    print("   OK - tkinter available")
except ImportError as e:
    print(f"   FAIL - {e}")

print("\n5. Full test - simulating viewer...")
try:
    import fitz
    from PIL import Image, ImageTk
    import io

    # Create a simple test PDF in memory
    test_pdf = b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000056 00000 n\n0000000115 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n206\n%%EOF'

    # Try to open it
    doc = fitz.open(stream=test_pdf, filetype="pdf")
    print(f"   OK - Can open PDF in memory, pages: {len(doc)}")
    doc.close()

except Exception as e:
    print(f"   FAIL - {type(e).__name__}: {e}")

print("\nAll tests completed!")
