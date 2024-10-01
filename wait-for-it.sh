#!/bin/sh
set -e

host="mysql"
port="3306"
cmd="$@"

until nc -z $host $port; do
  >&2 echo "MySQL is unavailable - sleeping"
  sleep 1
done

>&2 echo "MySQL is up - executing command"
exec $cmd