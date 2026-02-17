#!/bin/sh
set -e

gunicorn app:app --bind 0.0.0.0:5002 --workers 1 --timeout 180 &

nginx -g "daemon off;"
