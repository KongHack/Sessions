<?php

declare(strict_types=1);

namespace GCWorld\Sessions\Tests;

use GCWorld\Sessions\RedisSessionHandler;
use GCWorld\Sessions\SessionConfig;
use GCWorld\Sessions\SessionManager;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Ramsey\Uuid\Uuid;
use Redis;

final class SessionManagerTest extends RedisTestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLifecycleCsrfFlashAndAuthenticationWindow(): void
    {
        $now = 1700000000;
        $config = new SessionConfig(
            cookieName: 'GCWTEST',
            keyPrefix: 'TEST:MANAGER:',
            idleTtl: 120,
            authenticatedTtl: 300,
            reauthPromptLead: 60,
            cookieSecure: false,
            clock: static function () use (&$now): int {
                return $now;
            },
        );
        $handler = new RedisSessionHandler($this->redis, $config);
        $manager = new SessionManager($handler, $config);

        self::assertTrue($manager->start());
        self::assertTrue(Uuid::isValid(session_id()));

        $csrf = $manager->getCsrfToken('login');
        self::assertTrue($manager->validateCsrfToken($csrf, 'login'));
        self::assertFalse($manager->validateCsrfToken('incorrect', 'login'));

        $manager->addFlash('Welcome back', 'success');
        self::assertSame(
            [['message' => 'Welcome back', 'class' => 'success']],
            $manager->consumeFlash(),
        );
        self::assertSame([], $manager->consumeFlash());

        $oldId = session_id();
        $manager->authenticate(42);
        self::assertNotSame($oldId, session_id());
        self::assertSame('42', $manager->getSubjectId());
        self::assertSame(SessionManager::AUTH_STATE_OK, $manager->getAuthenticationStatus()['state']);

        $now += 250;
        self::assertSame(SessionManager::AUTH_STATE_PROMPT, $manager->getAuthenticationStatus()['state']);
        $now += 51;
        self::assertSame(SessionManager::AUTH_STATE_REQUIRED, $manager->getAuthenticationStatus()['state']);

        $manager->refreshAuthentication();
        self::assertSame(SessionManager::AUTH_STATE_OK, $manager->getAuthenticationStatus()['state']);

        $manager->recordUri('/account');
        self::assertSame('/account', $manager->getUriHistory()[0]['uri']);
        self::assertContains(session_id(), $handler->getSubjectSessions('42'));

        $authenticatedSessionId = session_id();
        $manager->logout();
        self::assertSame(PHP_SESSION_NONE, session_status());
        self::assertNotContains($authenticatedSessionId, $handler->getSubjectSessions('42'));
    }

    protected function setUp(): void
    {
        $this->redis = new Redis();
        $connected = $this->redis->connect(
            (string) (getenv('GCWORLD_SESSIONS_REDIS_HOST') ?: 'redis'),
            (int) (getenv('GCWORLD_SESSIONS_REDIS_PORT') ?: 6379),
        );
        self::assertTrue($connected);
        $this->redis->select(15);
        $this->redis->flushDB();
    }
}
