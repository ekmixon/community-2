# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidGooglePlayDiff(Signature):
    name = "android_google_play_diff"
    description = "Application Permissions On Google Play Differ (Osint)"
    severity = 3
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        apk_permission_list = [
            perm["name"]
            for perm in self.get_apkinfo("manifest", {}).get("permissions", [])
        ]

        google_permission_list = list(self.get_googleplay("permissions", []))
        if permission_diff := list(
            set(google_permission_list) - set(apk_permission_list)
        ):
            self.mark(permissions=permission_diff)
            return True
