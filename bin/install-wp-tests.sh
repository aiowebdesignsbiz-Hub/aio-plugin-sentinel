#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: $0 <db-name> <db-user> <db-password> <db-host> [wp-version]"
  exit 1
fi

DB_NAME="$1"
DB_USER="$2"
DB_PASS="$3"
DB_HOST="$4"
WP_VERSION="${5:-latest}"
WP_TESTS_REF="trunk"
WP_TESTS_DIR="${WP_TESTS_DIR:-/tmp/wordpress-tests-lib}"
WP_CORE_DIR="${WP_CORE_DIR:-/tmp/wordpress}"

if [ "$WP_VERSION" != "latest" ]; then
  WP_TESTS_REF="tags/${WP_VERSION}"
fi

if [ ! -d "$WP_CORE_DIR" ]; then
  mkdir -p "$WP_CORE_DIR"
  if [ "$WP_VERSION" = "latest" ]; then
    curl -sL https://wordpress.org/latest.tar.gz | tar xz --strip-components=1 -C "$WP_CORE_DIR"
  else
    curl -sL "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz" | tar xz --strip-components=1 -C "$WP_CORE_DIR"
  fi
fi

if [ ! -d "$WP_TESTS_DIR" ]; then
  mkdir -p "$WP_TESTS_DIR"
  # PHPUnit compatibility files live in nested test-suite directories.
  svn co "https://develop.svn.wordpress.org/${WP_TESTS_REF}/tests/phpunit/includes/" "$WP_TESTS_DIR/includes"
  svn co "https://develop.svn.wordpress.org/${WP_TESTS_REF}/tests/phpunit/data/" "$WP_TESTS_DIR/data"
fi

if [ ! -f "$WP_TESTS_DIR/wp-tests-config.php" ]; then
  curl -sL "https://develop.svn.wordpress.org/${WP_TESTS_REF}/wp-tests-config-sample.php" > "$WP_TESTS_DIR/wp-tests-config.php"
  sed -i "s/youremptytestdbnamehere/$DB_NAME/" "$WP_TESTS_DIR/wp-tests-config.php"
  sed -i "s/yourusernamehere/$DB_USER/" "$WP_TESTS_DIR/wp-tests-config.php"
  sed -i "s/yourpasswordhere/$DB_PASS/" "$WP_TESTS_DIR/wp-tests-config.php"
  sed -i "s|localhost|$DB_HOST|" "$WP_TESTS_DIR/wp-tests-config.php"
  sed -i "s|dirname( __FILE__ ) . '/src/'|'$WP_CORE_DIR/'|" "$WP_TESTS_DIR/wp-tests-config.php"
fi

echo "WordPress test environment installed at $WP_TESTS_DIR"
