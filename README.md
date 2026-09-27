# GCWorld Sessions

Redis-backed PHP sessions for PHP 8.4 applications.

### Version
0.1.0

The package keeps PHP's session lifecycle and `php_serialize` payload format,
but replaces native file storage with an application-owned Redis handler. It
provides UUID session IDs, Redis-backed expiration and locking, secure cookie
configuration, per-subject session indexes, session rotation, CSRF tokens,
flash messages, URI history, and authentication-window state.

The core has no application, tenant, ORM, or member-model dependency. Subject
identifiers are opaque strings, allowing consumers to use integer IDs, UUIDs,
or another stable identifier.

## Requirements

- PHP 8.4+
- ext-redis
- A dedicated Redis connection

## Basic usage

```php
use GCWorld\Sessions\SessionConfig;
use GCWorld\Sessions\SessionManager;
use GCWorld\Sessions\RedisSessionHandler;

$redis = new Redis();
$redis->connect('redis');
$redis->select(1);

$config = new SessionConfig(
    cookieName: '__Host-KHSID',
    keyPrefix: 'KONGHACK:SESSION:',
);

$handler = new RedisSessionHandler($redis, $config);
$session = new SessionManager($handler, $config);
$session->start();
```

Configure PHP before starting a session:

```ini
session.save_handler = user
session.serialize_handler = php_serialize
```

`SessionManager::start()` registers the user handler and enforces
`php_serialize` at runtime as a safety net.

## Development

```shell
./dc up -d
./dc exec -T php composer install
./dc exec -T php composer check
```
