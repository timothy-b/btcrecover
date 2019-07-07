io = None
tstr = None
tstr_from_stdin = None
tchr = None


# One of these two is typically called relatively early by parse_arguments()
def enable_unicode_mode():
    global io, tstr, tstr_from_stdin, tchr
    import locale, io
    tstr = unicode
    preferredencoding = locale.getpreferredencoding()
    tstr_from_stdin = lambda s: s if isinstance(s, unicode) else unicode(s, preferredencoding)
    tchr = unichr


def enable_ascii_mode():
    global io, tstr, tstr_from_stdin, tchr
    io = None
    tstr = str
    tstr_from_stdin = str
    tchr = chr
