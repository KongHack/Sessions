<?php

declare(strict_types=1);

namespace GCWorld\Sessions\Tests;

use GCWorld\Sessions\Exception\SessionLockException;
use GCWorld\Sessions\RedisSessionHandler;
use GCWorld\Sessions\SessionConfig;
use Ramsey\Uuid\Uuid;

final class RedisSessionHandlerTest extends RedisTestCase
{
    public function testPersistsPayloadMetadataAndExpiration(): void
    {
        $now = 1700000000;
        $config = $this->config($now);
        $handler = new RedisSessionHandler($this->redis, $config);
        $id = $handler->create_sid();

        self::assertSame('', $handler->read($id));
        self::assertTrue($handler->write($id, 'serialized-session-data'));
        self::assertTrue($handler->set('custom', 'value'));
        self::assertSame('value', $handler->get('custom'));
        self::assertGreaterThan(0, $this->redis->ttl($config->keyPrefix . $id));
        $handler->close();

        $reloaded = new RedisSessionHandler($this->redis, $config);
        self::assertSame('serialized-session-data', $reloaded->read($id));
        self::assertSame('value', $reloaded->get('custom'));
        $reloaded->close();
    }

    public function testIndexesAndRevokesSessionsByOpaqueSubject(): void
    {
        $now = 1700000000;
        $config = $this->config($now);
        $first = new RedisSessionHandler($this->redis, $config);
        $firstId = $first->create_sid();
        $first->read($firstId);
        $first->set(RedisSessionHandler::FIELD_SUBJECT_ID, '42');
        $first->write($firstId, 'first');
        $first->close();

        $second = new RedisSessionHandler($this->redis, $config);
        $secondId = $second->create_sid();
        $second->read($secondId);
        $second->set(RedisSessionHandler::FIELD_SUBJECT_ID, '42');
        $second->write($secondId, 'second');
        $second->close();

        self::assertEqualsCanonicalizing([$firstId, $secondId], $second->getSubjectSessions('42'));
        self::assertSame(1, $second->revokeSubjectSessions('42', $secondId));
        self::assertSame([$secondId], $second->getSubjectSessions('42'));
    }

    public function testUriHistoryIsBounded(): void
    {
        $now = 1700000000;
        $config = $this->config($now, uriHistoryLength: 2);
        $handler = new RedisSessionHandler($this->redis, $config);
        $id = $handler->create_sid();
        $handler->read($id);
        $handler->addUri('/one');
        ++$now;
        $handler->addUri('/two');
        ++$now;
        $handler->addUri('/three');

        self::assertSame(['/three', '/two'], array_column($handler->getUriHistory(), 'uri'));
        $handler->close();
    }

    public function testStrictValidationRejectsUnknownAndMalformedIds(): void
    {
        $now = 1700000000;
        $handler = new RedisSessionHandler($this->redis, $this->config($now));

        self::assertFalse($handler->validateId('not-a-uuid'));
        self::assertFalse($handler->validateId(Uuid::uuid4()->toString()));

        $id = $handler->create_sid();
        $handler->read($id);
        $handler->close();
        self::assertTrue($handler->validateId($id));
    }

    public function testConcurrentAccessTimesOutOnHeldLock(): void
    {
        $now = 1700000000;
        $config = $this->config($now, lockWaitMilliseconds: 20);
        $first = new RedisSessionHandler($this->redis, $config);
        $id = $first->create_sid();
        $first->read($id);

        $second = new RedisSessionHandler($this->redis, $config);
        $this->expectException(SessionLockException::class);
        try {
            $second->read($id);
        } finally {
            $first->close();
        }
    }

    private function config(
        int &$now,
        int $uriHistoryLength = 25,
        int $lockWaitMilliseconds = 100,
    ): SessionConfig {
        return new SessionConfig(
            cookieName: 'GCWTEST',
            keyPrefix: 'TEST:SESSION:',
            idleTtl: 120,
            authenticatedTtl: 300,
            reauthPromptLead: 60,
            cookieSecure: false,
            lockWaitMilliseconds: $lockWaitMilliseconds,
            uriHistoryLength: $uriHistoryLength,
            clock: static function () use (&$now): int {
                return $now;
            },
        );
    }
}
