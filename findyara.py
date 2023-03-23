# -*- coding: utf-8 -*-
"""
########################################################################################
## Author: @herrcore
## Original-Project-Link: https://github.com/OALabs/findyara-ida

## Fork-Author: @Tera0017 (Fork-Version: "x.x.666")
## Fork-Link: https://github.com/Tera0017/findyara-ida

## Thanks to @herrcore for this amazing project have been using this tool for quite some years
########################################################################################
"""
import idc
import idaapi
import idautils

import yara
import string
import operator

__AUTHOR__ = '@herrcore'
__FORK_AUTHOR__ = '@Tera0017'
# lost the count :P
VERSION = "x.x.666"
# FindYara finds yara rule
PLUGIN_NAME = 'FindYara'
PLUGIN_HOTKEY = "Ctrl-Alt-Y"
BANNER = f"""
=============================================================
___________.__             .________.___.                       
\_   _____/|__|  ____    __| _/\__  |   |_____  _______ _____   
 |    __)  |  | /    \  / __ |  /   |   |\__  \ \_  __ \\\\__  \  
 |     \   |  ||   |  \/ /_/ |  \____   | / __ \_|  | \/ / __ \_
 \___  /   |__||___|  /\____ |  / ______|(____  /|__|   (____  /
     \/             \/      \/  \/            \/             \/ 
* {PLUGIN_NAME} by {__FORK_AUTHOR__} (Fork-Version: "{VERSION}")
* {PLUGIN_NAME} by {__AUTHOR__} (Initial project)
** {PLUGIN_NAME} search shortcut key is {PLUGIN_HOTKEY}
** Original-Project-Link: https://github.com/OALabs/findyara-ida
** Fork-Link: https://github.com/Tera0017/findyara-ida
=============================================================
""".strip()

P_INITIALIZED = False


class Kp_Menu_Context(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @classmethod
    def get_name(cls):
        return cls.__name__

    @classmethod
    def get_label(cls):
        return cls.label

    @classmethod
    def register(cls, plugin, label):
        cls.plugin = plugin
        cls.label = label
        instance = cls()
        return idaapi.register_action(idaapi.action_desc_t(
            cls.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(cls):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    @classmethod
    def activate(cls, ctx):
        # dummy method
        return 1

    @classmethod
    def update(cls, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class Searcher(Kp_Menu_Context):
    def activate(self, ctx):
        self.plugin.search()
        return 1


class YaraSearchResultChooser(idaapi.Choose):
    """Class responsible for how result will be viewed in IDA.
    """
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False):
        result_columns = [
            # function of address of matched yara string
            ["Function", idaapi.Choose.CHCOL_PLAIN | 20],
            # address of matched yara string
            ["Address", idaapi.Choose.CHCOL_HEX | 20],
            # yara rule matched name (rule)
            ["Rule Name", idaapi.Choose.CHCOL_PLAIN | 30],
            # yara rule matched string
            ["Match", idaapi.Choose.CHCOL_PLAIN | 40],
            # yara rule matched string data
            ["Data", idaapi.Choose.CHCOL_PLAIN | 20],
        ]
        idaapi.Choose.__init__(self, title, result_columns, flags=flags, width=width, height=height, embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][1])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [res[0], idc.atoa(res[1]), res[2], res[3], res[4]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0


def print_msg(msg: str) -> None:
    """ Prints formatted message in IDA console.
    @param msg: message to print
    @return: None
    """
    print(f'>>> {msg}')


class YaraSearch(object):
    def __init__(self, yara_rule: str, plugin_name: str):
        self.yara_rule = yara_rule
        self.plugin_name = plugin_name
        self.rules = self.compile_yara()

    def compile_yara(self) -> yara.Rules:
        print_msg(f"Yara rules:\n{self.yara_rule}")
        print_msg(f"Yara version: \"{yara.__version__}\"")
        try:
            return yara.compile(source=self.yara_rule)
        except Exception as e:
            print_msg(f"ERROR: Cannot compile Yara rules from\n{self.yara_rule}")
            print_msg(f"Exception: \"{e}\"")
            raise Exception('Error Compiling Yara Rule')

    @staticmethod
    def _get_memory() -> (bytes, [(int, int, int)]):
        def lrange(num1, num2=None, step=1) -> [int]:
            op = operator.__lt__
            if num2 is None:
                num1, num2 = 0, num1
            if num2 < num1:
                if step > 0:
                    num1 = num2
                op = operator.__gt__
            elif step < 0:
                num1 = num2
            while op(num1, num2):
                yield num1
                num1 += step

        result = b''
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_end(start)
            result += bytes([idc.get_wide_byte(ea) for ea in lrange(start, end)])
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result, offsets

    def yara_search(self, memory: bytes, offsets: [(int, int, int)]) -> [[str, int, str, str, str]]:
        """Searches Yara rules in memory and provides formatted list to print into IDA
        @param memory: bytes to searhc yara rules
        @param offsets: offsets
        @return: [[str_function_name, int_matched_addr, str_matched_rule, str_matched_str, str_matched_type]]
        """
        def is_ida_printable(data: bytes, tp: str) -> bool:
            """ Checks if IDA printable characters
            @param data: bytes to print
            @param tp: utf8/utf16
            @return: bool
            """
            try:
                return all([i in string.printable for i in data.decode(tp)])
            except UnicodeDecodeError:
                pass
            return False

        def tova(offset: int, segments: [(int, int, int)]):
            """Returns Virtual Address of Match
            @param offset: matched offset
            @param segments: list of offsets
            @return: va of matched offset
            """
            va_offset = 0
            for seg in segments:
                if seg[1] <= offset < seg[2]:
                    va_offset = seg[0] + (offset - seg[1])
            return va_offset

        print_msg("Start yara search")
        matches = self.rules.match(data=memory)
        print_msg(f"Matched Rules: {', '.join([match.rule for match in matches])}")
        values = []
        for rule_match in matches:
            # matched yara rule name
            name = rule_match.rule
            for match in rule_match.strings:
                # matched string
                match_string = match[2]
                # string type
                match_type = 'ascii'
                if not is_ida_printable(match_string, 'utf-8'):
                    if is_ida_printable(match_string, 'utf16'):
                        match_string = match_string.decode('utf-16')
                        match_type = 'wide'
                    else:
                        match_string = " ".join("{:02x}".format(c) for c in match_string)
                        match_type = 'binary'
                else:
                    match_string = match_string.decode('utf-8')
                match_addr = tova(match[0], offsets)
                func_name = idc.get_func_name(idc.get_func_attr(match_addr, idc.FUNCATTR_START))
                prnt_match = [
                    'N/A' if not func_name else func_name,
                    match_addr,
                    '{}->{}'.format(name, match[1]),
                    match_string,
                    match_type
                ]
                values.append(prnt_match)
        print_msg("End yara search")
        return values

    def search(self) -> None:
        """Gets memory data, compiles yara rule and searches memory.
        @return: None
        """
        # Get binary memory data.
        memory, offsets = self._get_memory()
        # Search Yara rule through memory
        values = self.yara_search(memory, offsets)
        # Show results
        c = YaraSearchResultChooser(f"{self.plugin_name} scan results", values)
        _ = c.show()


class FindYara_Plugin_t(idaapi.plugin_t):
    comment = f"{PLUGIN_NAME} plugin for IDA Pro (using yara framework)"
    help = "Still todo..."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global P_INITIALIZED

        # register popup menu handlers
        try:
            Searcher.register(self, PLUGIN_NAME)
        except AttributeError:
            pass

        if P_INITIALIZED is False:
            P_INITIALIZED = True
            idaapi.register_action(idaapi.action_desc_t(PLUGIN_NAME, "Find Yara rule matches!", YaraSearch.search,
                None, None, 0))
            idaapi.attach_action_to_menu(f"Edit/{PLUGIN_NAME}", PLUGIN_NAME, idaapi.SETMENU_APP)
            print(BANNER)
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def term():
        pass

    def run(self, arg) -> None:
        """Initial function which asks user for a file. Allowed extensions are ".yar*"
        @return:
        """
        yara_file = idaapi.ask_file(0, "*.yar*", 'Choose Yara File...')
        if yara_file is None:
            print_msg("[ERROR] You must choose a yara file to scan with")
            return
        with open(yara_file, 'r') as fp:
            yara_rule = fp.read()
        # searches yara rule
        find_yara = YaraSearch(yara_rule, self.wanted_name)
        find_yara.search()


# register IDA plugin
def PLUGIN_ENTRY():
    return FindYara_Plugin_t()
