<?php

declare(strict_types=1);

namespace GCWorld\Sessions;

use GCWorld\Sessions\Exception\SessionLockException;
use InvalidArgumentException;
use Ramsey\Uuid\Uuid;
use Redis;
use SessionHandlerInterface;
use SessionIdInterface;
use SessionUpdateTimestampHandlerInterface;

final class RedisSessionHandler implements
    SessionHandlerInterface,
    SessionIdInterface,
    SessionUpdateTimestampHandlerInterface
{
    public const FIELD_RAW = 'raw';
    public const FIELD_CREATED_AT = 'created_at';
    public const FIELD_LAST_SEEN_AT = 'last_seen_at';
    public const FIELD_SUBJECT_ID = 'subject_id';

    /** @var array<string, mixed> */
    private array $data = [];
    private ?string $sessionId = null;
    private ?string $sessionKey = null;
    private ?string $lockKey = null;
    private ?string $lockToken = null;

    public function __construct(
        private readonly Redis $redis,
        private readonly SessionConfig $config,
    ) {
    }

    public function open(string $path, string $name): bool
    {
        unset($path, $name);

        return $this->redis->isConnected();
    }

    public function close(): bool
    {
        $this->releaseLock();

        return true;
    }

    public function read(string $id): string
    {
        if (!Uuid::isValid($id)) {
            return '';
        }

        $this->bindSessionId($id);
        $this->acquireLock();
        $loaded = $this->redis->hGetAll($this->sessionKey);
        $this->data = is_array($loaded) ? $loaded : [];

        $now = $this->config->now();
        if ($this->data === []) {
            $this->data = [
                self::FIELD_CREATED_AT => $now,
                self::FIELD_LAST_SEEN_AT => $now,
            ];
            $this->redis->hMSet($this->sessionKey, $this->data);
        } else {
            $this->data[self::FIELD_LAST_SEEN_AT] = $now;
            $this->redis->hSet($this->sessionKey, self::FIELD_LAST_SEEN_AT, $now);
        }
        $this->touchKeys();

        $raw = $this->data[self::FIELD_RAW] ?? '';

        return is_string($raw) ? $raw : '';
    }

    public function write(string $id, string $data): bool
    {
        if (!Uuid::isValid($id)) {
            return false;
        }
        if ($this->sessionId !== $id) {
            $this->releaseLock();
            $this->bindSessionId($id);
            $this->acquireLock();
        }

        $now = $this->config->now();
        $created = $this->data[self::FIELD_CREATED_AT] ?? $now;
        $this->data[self::FIELD_RAW] = $data;
        $this->data[self::FIELD_CREATED_AT] = $created;
        $this->data[self::FIELD_LAST_SEEN_AT] = $now;

        $saved = $this->redis->hMSet($this->sessionKey, [
            self::FIELD_RAW => $data,
            self::FIELD_CREATED_AT => $created,
            self::FIELD_LAST_SEEN_AT => $now,
        ]);
        $this->touchKeys();

        return $saved;
    }

    public function destroy(string $id): bool
    {
        if (!Uuid::isValid($id)) {
            return true;
        }

        $key = $this->sessionKey($id);
        $subject = $this->redis->hGet($key, self::FIELD_SUBJECT_ID);
        if (is_string($subject) && $subject !== '') {
            $this->redis->sRem($this->subjectKey($subject), $id);
        }

        $this->redis->del($key, $this->uriKey($id), $this->lockKey($id));
        if ($this->sessionId === $id) {
            $this->data = [];
            $this->sessionId = null;
            $this->sessionKey = null;
            $this->lockKey = null;
            $this->lockToken = null;
        }

        return true;
    }

    public function gc(int $max_lifetime): int
    {
        unset($max_lifetime);

        return 0;
    }

    // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps -- PHP's SessionIdInterface mandates this name.
    public function create_sid(): string
    {
        return Uuid::uuid4()->toString();
    }

    public function validateId(string $id): bool
    {
        return Uuid::isValid($id) && $this->redis->exists($this->sessionKey($id)) > 0;
    }

    public function updateTimestamp(string $id, string $data): bool
    {
        return $this->write($id, $data);
    }

    public function bindSessionId(string $id): void
    {
        if (!Uuid::isValid($id)) {
            throw new InvalidArgumentException('Session IDs must be valid UUIDs.');
        }

        $this->sessionId = $id;
        $this->sessionKey = $this->sessionKey($id);
        $this->lockKey = $this->lockKey($id);
        $loaded = $this->redis->hGetAll($this->sessionKey);
        $this->data = is_array($loaded) ? $loaded : [];
    }

    public function set(string $key, mixed $value): bool
    {
        $this->requireBoundSession();
        $previous = $this->data[$key] ?? null;
        if ($value === null) {
            if ($key === self::FIELD_SUBJECT_ID && is_scalar($previous) && (string) $previous !== '') {
                $this->redis->sRem($this->subjectKey((string) $previous), $this->sessionId);
            }
            unset($this->data[$key]);

            return $this->redis->hDel($this->sessionKey, $key) >= 0;
        }
        if (!is_scalar($value)) {
            throw new InvalidArgumentException('Session metadata must be scalar or null.');
        }

        if (
            $key === self::FIELD_SUBJECT_ID
            && is_scalar($previous)
            && (string) $previous !== (string) $value
        ) {
            $this->redis->sRem($this->subjectKey((string) $previous), $this->sessionId);
        }

        $this->data[$key] = $value;
        $saved = $this->redis->hSet($this->sessionKey, $key, $value);

        if ($key === self::FIELD_SUBJECT_ID && (string) $value !== '') {
            $subjectKey = $this->subjectKey((string) $value);
            $this->redis->sAdd($subjectKey, $this->sessionId);
            $this->redis->expire($subjectKey, $this->config->authenticatedTtl + $this->config->idleTtl);
        }
        $this->touchKeys();

        return $saved !== false;
    }

    public function get(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }

    /** @return array<string, mixed> */
    public function getAll(): array
    {
        return $this->data;
    }

    public function getSessionKey(): ?string
    {
        return $this->sessionId;
    }

    /** @return list<string> */
    public function getSubjectSessions(string $subjectId): array
    {
        $sessions = $this->redis->sMembers($this->subjectKey($subjectId));
        if (!is_array($sessions)) {
            return [];
        }

        $active = [];
        foreach ($sessions as $id) {
            if (!is_string($id) || $this->redis->exists($this->sessionKey($id)) < 1) {
                if (is_string($id)) {
                    $this->redis->sRem($this->subjectKey($subjectId), $id);
                }
                continue;
            }
            $active[] = $id;
        }

        return $active;
    }

    public function revokeSubjectSessions(string $subjectId, ?string $exceptSessionId = null): int
    {
        $count = 0;
        foreach ($this->getSubjectSessions($subjectId) as $id) {
            if ($exceptSessionId !== null && hash_equals($exceptSessionId, $id)) {
                continue;
            }
            $this->destroy($id);
            ++$count;
        }

        return $count;
    }

    public function addUri(string $uri): void
    {
        $this->requireBoundSession();
        $key = $this->uriKey($this->sessionId);
        $this->redis->lPush($key, $uri . '|' . $this->config->now());
        $this->redis->lTrim($key, 0, $this->config->uriHistoryLength - 1);
        $this->redis->expire($key, $this->config->idleTtl);
    }

    /** @return list<array{uri: string, time: int}> */
    public function getUriHistory(?string $sessionId = null): array
    {
        $id = $sessionId ?? $this->sessionId;
        if ($id === null || !Uuid::isValid($id)) {
            return [];
        }

        $rows = $this->redis->lRange($this->uriKey($id), 0, $this->config->uriHistoryLength - 1);
        if (!is_array($rows)) {
            return [];
        }

        $history = [];
        foreach ($rows as $row) {
            if (!is_string($row)) {
                continue;
            }
            [$uri, $time] = array_pad(explode('|', $row, 2), 2, '0');
            $history[] = ['uri' => $uri, 'time' => (int) $time];
        }

        return $history;
    }

    public function getRedis(): Redis
    {
        return $this->redis;
    }

    private function acquireLock(): void
    {
        if ($this->lockToken !== null) {
            return;
        }
        $this->requireBoundSession();

        $token = bin2hex(random_bytes(16));
        $deadline = microtime(true) + ($this->config->lockWaitMilliseconds / 1000);
        do {
            $locked = $this->redis->set(
                $this->lockKey,
                $token,
                ['nx', 'px' => $this->config->lockTtlMilliseconds],
            );
            if ($locked === true) {
                $this->lockToken = $token;

                return;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);

        throw new SessionLockException('Timed out waiting for the Redis session lock.');
    }

    private function releaseLock(): void
    {
        if ($this->lockToken === null || $this->lockKey === null) {
            return;
        }

        $script = <<<'LUA'
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
LUA;
        $this->redis->eval($script, [$this->lockKey, $this->lockToken], 1);
        $this->lockToken = null;
    }

    private function touchKeys(): void
    {
        $this->requireBoundSession();
        $this->redis->expire($this->sessionKey, $this->config->idleTtl);
    }

    private function requireBoundSession(): void
    {
        if ($this->sessionId === null || $this->sessionKey === null) {
            throw new InvalidArgumentException('No session ID is bound to the Redis handler.');
        }
    }

    private function sessionKey(string $id): string
    {
        return $this->config->keyPrefix . $id;
    }

    private function lockKey(string $id): string
    {
        return $this->config->keyPrefix . 'LOCK:' . $id;
    }

    private function uriKey(string $id): string
    {
        return $this->config->keyPrefix . 'URI:' . $id;
    }

    private function subjectKey(string $subjectId): string
    {
        return $this->config->keyPrefix . 'SUBJECT:' . hash('sha256', $subjectId);
    }
}
