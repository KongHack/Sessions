<?php

declare(strict_types=1);

namespace GCWorld\Sessions;

use GCWorld\Sessions\Exception\SessionConfigurationException;
use GCWorld\Sessions\Exception\SessionNotStartedException;

final class SessionManager
{
    private const STATE_KEY = '_gcworld_session';
    private const FLASH_KEY = 'flash';
    private const CSRF_KEY = 'csrf';
    private const SUBJECT_KEY = 'subject_id';
    private const AUTHENTICATED_AT_KEY = 'authenticated_at';
    private const AUTH_EXPIRES_AT_KEY = 'auth_expires_at';
    private const REAUTH_PROMPT_AT_KEY = 'reauth_prompt_at';

    public const AUTH_STATE_ANONYMOUS = 'anonymous';
    public const AUTH_STATE_OK = 'ok';
    public const AUTH_STATE_PROMPT = 'prompt';
    public const AUTH_STATE_REQUIRED = 'required';

    public function __construct(
        private readonly RedisSessionHandler $handler,
        private readonly SessionConfig $config,
    ) {
    }

    public function start(): bool
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $this->synchronizeHandler();

            return true;
        }

        if (headers_sent($file, $line)) {
            throw new SessionConfigurationException(
                sprintf('Cannot start the session after headers were sent at %s:%d.', $file, $line),
            );
        }

        if (ini_set('session.serialize_handler', 'php_serialize') === false) {
            throw new SessionConfigurationException('Unable to configure session.serialize_handler=php_serialize.');
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');

        session_name($this->config->cookieName);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $this->config->cookiePath,
            'domain' => $this->config->cookieDomain ?? '',
            'secure' => $this->config->cookieSecure,
            'httponly' => $this->config->cookieHttpOnly,
            'samesite' => $this->config->cookieSameSite,
        ]);
        session_set_save_handler($this->handler, true);
        if (ini_get('session.save_handler') !== 'user') {
            throw new SessionConfigurationException('The user session handler was not registered.');
        }

        $started = session_start();
        if ($started) {
            $this->synchronizeHandler();
        }

        return $started;
    }

    public function regenerate(bool $deleteOldSession = true): bool
    {
        $this->requireStarted();
        $regenerated = session_regenerate_id($deleteOldSession);
        if ($regenerated) {
            $this->handler->bindSessionId(session_id());
            $this->synchronizeHandler();
        }

        return $regenerated;
    }

    public function authenticate(string|int $subjectId, bool $regenerate = true): void
    {
        $this->requireStarted();
        $subject = trim((string) $subjectId);
        if ($subject === '') {
            throw new \InvalidArgumentException('Authenticated subject IDs cannot be empty.');
        }
        if ($regenerate) {
            $this->regenerate();
        }

        $now = $this->config->now();
        $state = &$this->state();
        $state[self::SUBJECT_KEY] = $subject;
        $state[self::AUTHENTICATED_AT_KEY] = $now;
        $state[self::AUTH_EXPIRES_AT_KEY] = $now + $this->config->authenticatedTtl;
        $state[self::REAUTH_PROMPT_AT_KEY] = $state[self::AUTH_EXPIRES_AT_KEY]
            - $this->config->reauthPromptLead;

        $this->handler->set(RedisSessionHandler::FIELD_SUBJECT_ID, $subject);
        $this->handler->set(self::AUTHENTICATED_AT_KEY, $state[self::AUTHENTICATED_AT_KEY]);
        $this->handler->set(self::AUTH_EXPIRES_AT_KEY, $state[self::AUTH_EXPIRES_AT_KEY]);
        $this->handler->set(self::REAUTH_PROMPT_AT_KEY, $state[self::REAUTH_PROMPT_AT_KEY]);
    }

    public function refreshAuthentication(): void
    {
        $subject = $this->getSubjectId();
        if ($subject === null) {
            throw new SessionNotStartedException('Cannot refresh an anonymous authentication window.');
        }
        $this->authenticate($subject, false);
    }

    public function logout(): void
    {
        $this->requireStarted();
        $_SESSION = [];
        $this->handler->set(RedisSessionHandler::FIELD_SUBJECT_ID, null);
        session_destroy();

        setcookie($this->config->cookieName, '', [
            'expires' => $this->config->now() - 3600,
            'path' => $this->config->cookiePath,
            'domain' => $this->config->cookieDomain ?? '',
            'secure' => $this->config->cookieSecure,
            'httponly' => $this->config->cookieHttpOnly,
            'samesite' => $this->config->cookieSameSite,
        ]);
    }

    public function isAuthenticated(): bool
    {
        return $this->getSubjectId() !== null;
    }

    public function getSubjectId(): ?string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return null;
        }
        $subject = $this->state()[self::SUBJECT_KEY] ?? null;

        return is_scalar($subject) && (string) $subject !== '' ? (string) $subject : null;
    }

    /**
     * @return array{
     *   authenticated: bool,
     *   state: string,
     *   authenticated_at: int|null,
     *   auth_expires_at: int|null,
     *   reauth_prompt_at: int|null,
     *   seconds_until_prompt: int|null,
     *   seconds_until_expiry: int|null
     * }
     */
    public function getAuthenticationStatus(): array
    {
        $subject = $this->getSubjectId();
        if ($subject === null) {
            return [
                'authenticated' => false,
                'state' => self::AUTH_STATE_ANONYMOUS,
                'authenticated_at' => null,
                'auth_expires_at' => null,
                'reauth_prompt_at' => null,
                'seconds_until_prompt' => null,
                'seconds_until_expiry' => null,
            ];
        }

        $state = $this->state();
        $now = $this->config->now();
        $authenticatedAt = (int) ($state[self::AUTHENTICATED_AT_KEY] ?? $now);
        $expiresAt = (int) ($state[self::AUTH_EXPIRES_AT_KEY]
            ?? ($authenticatedAt + $this->config->authenticatedTtl));
        $promptAt = (int) ($state[self::REAUTH_PROMPT_AT_KEY]
            ?? ($expiresAt - $this->config->reauthPromptLead));
        $authState = match (true) {
            $now >= $expiresAt => self::AUTH_STATE_REQUIRED,
            $now >= $promptAt => self::AUTH_STATE_PROMPT,
            default => self::AUTH_STATE_OK,
        };

        return [
            'authenticated' => true,
            'state' => $authState,
            'authenticated_at' => $authenticatedAt,
            'auth_expires_at' => $expiresAt,
            'reauth_prompt_at' => $promptAt,
            'seconds_until_prompt' => max(0, $promptAt - $now),
            'seconds_until_expiry' => max(0, $expiresAt - $now),
        ];
    }

    public function getCsrfToken(string $scope = 'default'): string
    {
        $this->requireStarted();
        $state = &$this->state();
        if (!isset($state[self::CSRF_KEY]) || !is_array($state[self::CSRF_KEY])) {
            $state[self::CSRF_KEY] = [];
        }
        if (!isset($state[self::CSRF_KEY][$scope]) || !is_string($state[self::CSRF_KEY][$scope])) {
            $state[self::CSRF_KEY][$scope] = bin2hex(random_bytes(32));
        }

        return $state[self::CSRF_KEY][$scope];
    }

    public function validateCsrfToken(mixed $token, string $scope = 'default', bool $consume = false): bool
    {
        $this->requireStarted();
        $state = &$this->state();
        $stored = $state[self::CSRF_KEY][$scope] ?? null;
        $valid = is_string($token) && is_string($stored) && hash_equals($stored, $token);
        if ($valid && $consume) {
            unset($state[self::CSRF_KEY][$scope]);
        }

        return $valid;
    }

    public function addFlash(string $message, string $class = 'info'): void
    {
        $this->requireStarted();
        $state = &$this->state();
        if (!isset($state[self::FLASH_KEY]) || !is_array($state[self::FLASH_KEY])) {
            $state[self::FLASH_KEY] = [];
        }
        $state[self::FLASH_KEY][] = [
            'message' => $message,
            'class' => $class,
        ];
    }

    /** @return list<array{message: string, class: string}> */
    public function consumeFlash(): array
    {
        $this->requireStarted();
        $state = &$this->state();
        $messages = $state[self::FLASH_KEY] ?? [];
        unset($state[self::FLASH_KEY]);

        if (!is_array($messages)) {
            return [];
        }

        return array_values(array_filter(
            $messages,
            static fn (mixed $message): bool => is_array($message)
                && isset($message['message'], $message['class'])
                && is_string($message['message'])
                && is_string($message['class']),
        ));
    }

    public function recordUri(string $uri): void
    {
        $this->requireStarted();
        $this->handler->addUri($uri);
    }

    /** @return list<array{uri: string, time: int}> */
    public function getUriHistory(): array
    {
        return $this->handler->getUriHistory();
    }

    public function getHandler(): RedisSessionHandler
    {
        return $this->handler;
    }

    private function synchronizeHandler(): void
    {
        $id = session_id();
        if ($id !== '') {
            $this->handler->bindSessionId($id);
        }
        $subject = $this->getSubjectId();
        if ($subject !== null) {
            $this->handler->set(RedisSessionHandler::FIELD_SUBJECT_ID, $subject);
        }
    }

    /** @return array<string, mixed> */
    private function &state(): array
    {
        if (!isset($_SESSION[self::STATE_KEY]) || !is_array($_SESSION[self::STATE_KEY])) {
            $_SESSION[self::STATE_KEY] = [];
        }

        return $_SESSION[self::STATE_KEY];
    }

    private function requireStarted(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new SessionNotStartedException('The session has not been started.');
        }
    }
}
