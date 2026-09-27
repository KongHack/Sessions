<?php

declare(strict_types=1);

namespace GCWorld\Sessions\Tests;

use GCWorld\Sessions\Exception\SessionConfigurationException;
use GCWorld\Sessions\SessionConfig;
use PHPUnit\Framework\TestCase;

final class SessionConfigTest extends TestCase
{
    public function testHostCookieRequiresHostCookieRules(): void
    {
        $this->expectException(SessionConfigurationException::class);

        new SessionConfig(cookieName: '__Host-Test', cookieDomain: 'example.com');
    }

    public function testReauthenticationPromptMustFitInsideWindow(): void
    {
        $this->expectException(SessionConfigurationException::class);

        new SessionConfig(authenticatedTtl: 60, reauthPromptLead: 60);
    }
}
