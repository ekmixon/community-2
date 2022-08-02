# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class LolBot(Signature):
    name = "rat_lolbot"
    description = "Creates known LolBot Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["backdoor"]
    families = ["lolbot"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*\\\\Java\\\\jre-09\\\\bin\\\\Pfile.hlp",
        ".*\\\\Java\\\\jre-09\\\\bin\\\\dwntdux.hlp",
    ]

    def on_complete(self):
        return any(
            self.check_file(pattern=indicator, regex=True)
            for indicator in self.files_re
        )
