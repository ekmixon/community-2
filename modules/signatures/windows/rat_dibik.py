# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Dibik(Signature):
    name = "rat_dibik"
    description = "Creates known Dibik/Shark Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["dibik"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*\\$OK",
        ".*\\$AZ",
        ".*\\$ZR",
    ]

    files_re = [
        "C:\\\\Windows\\\\(system32|syswow64)\\\\eeS.EXE",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if match := self.check_mutex(pattern=indicator, regex=True):
                self.mark_ioc("mutex", match)

        for indicator in self.files_re:
            if match := self.check_file(pattern=indicator, regex=True):
                self.mark_ioc("file", match)

        return self.has_marks()
