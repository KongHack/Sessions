<?php

declare(strict_types=1);

namespace GCWorld\Sessions\Tests;

use PHPUnit\Framework\TestCase;
use Redis;

abstract class RedisTestCase extends TestCase
{
    protected Redis $redis;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Redis();
        $connected = $this->redis->connect(
            (string) (getenv('GCWORLD_SESSIONS_REDIS_HOST') ?: 'redis'),
            (int) (getenv('GCWORLD_SESSIONS_REDIS_PORT') ?: 6379),
        );
        self::assertTrue($connected);
        $this->redis->select(15);
        $this->redis->flushDB();
    }

    protected function tearDown(): void
    {
        $this->redis->flushDB();
        $this->redis->close();

        parent::tearDown();
    }
}
