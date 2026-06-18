# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in the AGP default file.

# Keep Bouncy Castle classes (needed for CMS/PKCS#7 at runtime)
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep PDFBox classes
-keep class com.tom_roush.pdfbox.** { *; }
-dontwarn com.tom_roush.pdfbox.**
