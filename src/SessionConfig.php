<?php

declare(strict_types=1);

namespace GCWorld\Sessions;

use Closure;
use GCWorld\Sessions\Exception\SessionConfigurationException;

final readonly class SessionConfig
{
    public function __construct(
        public string $cookieName = '__Host-GCWSID',
        public string $keyPrefix = 'GCWORLD:SESSION:',
        public int $idleTtl = 5400,
        public int $authenticatedTtl = 32400,
        public int $reauthPromptLead = 1800,
        public string $cookiePath = '/',
        public ?string $cookieDomain = null,
        public bool $cookieSecure = true,
        public bool $cookieHttpOnly = true,
        public string $cookieSameSite = 'Lax',
        public int $lockTtlMilliseconds = 30000,
        public int $lockWaitMilliseconds = 5000,
        public int $uriHistoryLength = 25,
        private ?Closure $clock = null,
    ) {
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $this->cookieName)) {
            throw new SessionConfigurationException('The session cookie name contains invalid characters.');
        }
        if ($this->keyPrefix === '') {
            throw new SessionConfigurationException('The Redis key prefix cannot be empty.');
        }
        if ($this->idleTtl < 1 || $this->authenticatedTtl < 1) {
            throw new SessionConfigurationException('Session lifetimes must be positive.');
        }
        if ($this->reauthPromptLead < 0 || $this->reauthPromptLead >= $this->authenticatedTtl) {
            throw new SessionConfigurationException('The reauthentication prompt must occur during the auth window.');
        }
        if (!in_array($this->cookieSameSite, ['Lax', 'Strict', 'None'], true)) {
            throw new SessionConfigurationException('Cookie SameSite must be Lax, Strict, or None.');
        }
        if ($this->cookieSameSite === 'None' && !$this->cookieSecure) {
            throw new SessionConfigurationException('SameSite=None cookies must be secure.');
        }
        if (str_starts_with($this->cookieName, '__Host-')) {
            if (!$this->cookieSecure || $this->cookiePath !== '/' || $this->cookieDomain !== null) {
                throw new SessionConfigurationException('__Host- cookies require Secure, Path=/, and no Domain.');
            }
        }
        if ($this->lockTtlMilliseconds < 1000 || $this->lockWaitMilliseconds < 0) {
            throw new SessionConfigurationException('Redis lock timing is invalid.');
        }
        if ($this->uriHistoryLength < 1) {
            throw new SessionConfigurationException('URI history length must be positive.');
        }
    }

    public function now(): int
    {
        return $this->clock === null ? time() : (int) ($this->clock)();
    }
}
