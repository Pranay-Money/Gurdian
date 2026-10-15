import locale

# Force UTF-8 across the process so Windows fixtures and localized content
# decode correctly even when the system code page is cp1252.
locale.getpreferredencoding = lambda do_setlocale=True: "UTF-8"
