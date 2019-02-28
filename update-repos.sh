#! /bin/sh

set -e

echo "Starting rpki.afrinic.net..."
openrsync --delete -rvlpt rsync://rpki.afrinic.net/repository/ repos/afrinic
echo "Finished with rpki.afrinic.net."

echo "Starting rpki.apnic.net..."
openrsync --delete -rvlpt rsync://rpki.apnic.net/repository/ repos/apnic
echo "Finished with rpki.apnic.net"

echo "Starting rpki.arin.net..."
openrsync --delete -rvlpt rsync://rpki.arin.net/repository/ repos/arin
echo "Finished with rpki.arin.net"

echo "Starting repository.lacnic.net..."
openrsync --delete -rvlpt rsync://repository.lacnic.net/rpki/ repos/lacnic
echo "Finished with repository.lacnic.net"

echo "Starting rpki.ripe.net..."
openrsync --delete -rvlpt rsync://rpki.ripe.net/repository/ repos/ripe
echo "Finished with rpki.ripe.net"
