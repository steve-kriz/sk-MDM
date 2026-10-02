#!/bin/sh
# Removes the OfficeHQ MDM agent from this Mac. Run as root:
#
#   sudo /usr/local/bin/mdmagent-uninstall.sh
#
# The daemon is booted out before anything is deleted, so launchd is not left
# holding a job whose binary and plist have gone. The bootout is best effort:
# a machine where the daemon never loaded must still end up clean.

launchctl bootout system /Library/LaunchDaemons/au.com.officehq.mdmagent.plist || true

rm -f /usr/local/bin/mdmagent
rm -f /Library/LaunchDaemons/au.com.officehq.mdmagent.plist
rm -rf "/Library/Application Support/OfficeHQ/MDM"

exit 0
