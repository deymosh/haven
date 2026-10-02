#!/bin/sh

if [ "$IMPORT_FLAG" = "true" ]; then
  exec /app/sanctum import
else
  exec /app/sanctum
fi