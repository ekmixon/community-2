# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Dapato(Signature):
    name = "trojan_dapato"
    description = "Creates known Dapato Trojan files, registry keys and/or mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["dapato"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*VistaDLLPro.*RUNNING",
        ".*VistaDLLPro.*Exit",
    ]

    files_re = [
        "C:\\\\WINDOWS\\\\(system32|syswow64)\\\\ipsecstap.dat",
        "C:\\\\WINDOWS\\\\Debug\\\\PASSW",
        "C:\\\\WINDOWS\\\\msip.ini",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if mutex := self.check_mutex(pattern=indicator, regex=True):
                self.mark_ioc("mutex", mutex)

        for indicator in self.files_re:
            if regkey := self.check_file(pattern=indicator, regex=True):
                self.mark_ioc("file", regkey)

        return self.has_marks()
