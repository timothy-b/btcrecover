from __future__ import print_function
import collections, string
import btcrecover.btrcpass.mode as mode

################################### Configurables/Plugins ###################################
# wildcard sets, simple typo generators

wildcard_sets = wildcard_keys = wildcard_nocase_sets = wildcard_re = None
custom_wildcard_cache = backreference_maps = backreference_maps_sha1 = None
simple_typos = simple_typo_args = None
typos_map = None
typos_replace_expanded = []


# Recognized wildcard (e.g. %d, %a) types mapped to their associated sets
# of characters; used in expand_wildcards_generator()
# warning: these can't be the key for a wildcard set: digits 'i' 'b' '[' ',' ';' '-' '<' '>'
def init_wildcards():
    global wildcard_sets, wildcard_keys, wildcard_nocase_sets, wildcard_re, \
        custom_wildcard_cache, backreference_maps, backreference_maps_sha1
    # N.B. that mode.tstr() will not convert string.*case to Unicode correctly if the locale has
    # been set to one with a single-byte code page e.g. ISO-8859-1 (Latin1) or Windows-1252
    wildcard_sets = {
        mode.tstr("d") : mode.tstr(string.digits),
        mode.tstr("a") : mode.tstr(string.lowercase),
        mode.tstr("A") : mode.tstr(string.uppercase),
        mode.tstr("n") : mode.tstr(string.lowercase + string.digits),
        mode.tstr("N") : mode.tstr(string.uppercase + string.digits),
        mode.tstr("s") : mode.tstr(" "),        # space
        mode.tstr("l") : mode.tstr("\n"),       # line feed
        mode.tstr("r") : mode.tstr("\r"),       # carriage return
        mode.tstr("R") : mode.tstr("\n\r"),     # newline characters
        mode.tstr("t") : mode.tstr("\t"),       # tab
        mode.tstr("T") : mode.tstr(" \t"),      # space and tab
        mode.tstr("w") : mode.tstr(" \r\n"),    # space and newline characters
        mode.tstr("W") : mode.tstr(" \r\n\t"),  # space, newline, and tab
        mode.tstr("y") : mode.tstr(string.punctuation),
        mode.tstr("Y") : mode.tstr(string.digits + string.punctuation),
        mode.tstr("p") : mode.tstr().join(map(mode.tchr, xrange(33, 127))),  # all ASCII printable characters except whitespace
        mode.tstr("P") : mode.tstr().join(map(mode.tchr, xrange(33, 127))) + mode.tstr(" \r\n\t"),  # as above, plus space, newline, and tab
        # wildcards can be used to escape these special symbols
        mode.tstr("%") : mode.tstr("%"),
        mode.tstr("^") : mode.tstr("^"),
        mode.tstr("S") : mode.tstr("$")  # the key is intentionally a capital "S", the value is a dollar sign
    }
    wildcard_keys = mode.tstr().join(wildcard_sets)
    #
    # case-insensitive versions (e.g. %ia) of wildcard_sets for those which have them
    wildcard_nocase_sets = {
        mode.tstr("a") : mode.tstr(string.lowercase + string.uppercase),
        mode.tstr("A") : mode.tstr(string.uppercase + string.lowercase),
        mode.tstr("n") : mode.tstr(string.lowercase + string.uppercase + string.digits),
        mode.tstr("N") : mode.tstr(string.uppercase + string.lowercase + string.digits)
    }
    #
    wildcard_re = None
    custom_wildcard_cache   = dict()
    backreference_maps      = dict()
    backreference_maps_sha1 = None


# Simple typo generators produce (as an iterable, e.g. a tuple, generator, etc.)
# zero or more alternative typo strings which can replace a single character. If
# more than one string is produced, all combinations are tried. If zero strings are
# produced (e.g. an empty tuple), then the specified input character has no typo
# alternatives that can be tried (e.g. you can't change the case of a caseless char).
# They are called with the full password and an index into that password of the
# character which will be replaced.
#
def typo_repeat(p, i): return 2 * p[i],  # A single replacement of len 2.
def typo_delete(p, i): return mode.tstr(""),  # A single replacement of len 0.
def typo_case(p, i):                     # Returns a single replacement or no
    swapped = p[i].swapcase()            # replacement if it's a caseless char.
    return (swapped,) if swapped != p[i] else ()


def typo_closecase(p, i):  #  Returns a swapped case only when case transitions are nearby
    cur_case_id = case_id_of(p[i])  # (case_id functions defined in the Password Generation section)
    if cur_case_id == UNCASED_ID: return ()
    if i==0 or i+1==len(p) or \
            case_id_changed(case_id_of(p[i-1]), cur_case_id) or \
            case_id_changed(case_id_of(p[i+1]), cur_case_id):
        return p[i].swapcase(),
    return ()


def typo_replace_wildcard(p, i): return [e for e in typos_replace_expanded if e != p[i]]
def typo_map(p, i):              return typos_map.get(p[i], ())
# (typos_replace_expanded and typos_map are initialized from args.typos_replace
# and args.typos_map respectively in parse_arguments() )
#
# a dict: command line argument name is: "typos-" + key_name; associated value is
# the generator function from above; this dict MUST BE ORDERED to prevent the
# breakage of --skip and --restore features (the order can be arbitrary, but it
# MUST be repeatable across runs and preferably across implementations)
simple_typos = collections.OrderedDict()
simple_typos["repeat"]    = typo_repeat
simple_typos["delete"]    = typo_delete
simple_typos["case"]      = typo_case
simple_typos["closecase"] = typo_closecase
simple_typos["replace"]   = typo_replace_wildcard
simple_typos["map"]       = typo_map


# a dict: typo name (matches typo names in the dict above) mapped to the options
# that are passed to add_argument; this dict is only ordered for cosmetic reasons
simple_typo_args = collections.OrderedDict()
simple_typo_args["repeat"]    = dict( action="store_true",       help="repeat (double) a character" )
simple_typo_args["delete"]    = dict( action="store_true",       help="delete a character" )
simple_typo_args["case"]      = dict( action="store_true",       help="change the case (upper/lower) of a letter" )
simple_typo_args["closecase"] = dict( action="store_true",       help="like --typos-case, but only change letters next to those with a different case")
simple_typo_args["map"]       = dict( metavar="FILE",            help="replace specific characters based on a map file" )
simple_typo_args["replace"]   = dict( metavar="WILDCARD-STRING", help="replace a character with another string or wildcard" )


# Convenience functions currently only used by config.typo_closecase()
#
UNCASED_ID   = 0
LOWERCASE_ID = 1
UPPERCASE_ID = 2
def case_id_of(letter):
    if   letter.islower(): return LOWERCASE_ID
    elif letter.isupper(): return UPPERCASE_ID
    else:                  return UNCASED_ID


# Note that  in order for a case to be considered changed, one of the two letters must be
# uppercase (i.e. lowercase to uncased isn't a case change, but uppercase to uncased is a
# case change, and of course lowercase to uppercase is too)
def case_id_changed(case_id1, case_id2):
    if case_id1 != case_id2 and (case_id1 == UPPERCASE_ID or case_id2 == UPPERCASE_ID):
          return True
    else: return False
