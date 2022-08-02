# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Decay(Signature):
    name = "decay"
    description = "Creates known Decay files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["decay"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*m_darkmutex",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if mutex := self.check_mutex(pattern=indicator, regex=True):
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
