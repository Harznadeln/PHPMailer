<?php

namespace PHPMailer\Test\PHPMailer;

use PHPMailer\PHPMailer\POP3;
use PHPUnit\Framework\TestCase;

final class POP3CharacterizationTest extends TestCase
{
    public function testDefaultValuesAndErrorLogAreEmpty(): void
    {
        $pop = new POP3();
        self::assertSame(110, POP3::DEFAULT_PORT);
        self::assertSame(30, POP3::DEFAULT_TIMEOUT);
        self::assertSame(0, $pop->do_debug);
        self::assertSame([], $pop->getErrors());
    }

    public function testServerResponseMustBeginWithExactOkPrefix(): void
    {
        $pop = new POP3Probe();
        self::assertTrue($pop->inspectResponse('+OK ready'));
        self::assertTrue($pop->inspectResponse('+OKextra')); // Observed prefix-only acceptance.
        self::assertFalse($pop->inspectResponse('-ERR invalid credentials'));
        self::assertFalse($pop->inspectResponse(' +OK ready'));
        self::assertCount(2, $pop->getErrors());
        self::assertStringContainsString('Server reported an error:', $pop->getErrors()[0]);
    }

    public function testControlCharactersAreRemovedFromCredentials(): void
    {
        self::assertSame('abc', POP3Probe::clean('a' . "\0\r\nb\t" . 'c' . "\x7f"));
        self::assertSame('', POP3Probe::clean("\0\r\n\t"));
    }

    public function testErrorsAndPhpWarningsAreStoredAndDebugOutputIsOptional(): void
    {
        $pop = new POP3Probe();
        $pop->recordError('first error');
        $pop->simulateWarning(8, 'demo warning', 'test.php', 42);
        self::assertCount(2, $pop->getErrors());
        self::assertSame('first error', $pop->getErrors()[0]);
        self::assertStringContainsString('errno: 8', $pop->getErrors()[1]);
        self::assertStringContainsString('demo warning', $pop->getErrors()[1]);

        $pop->do_debug = POP3::DEBUG_SERVER;
        ob_start();
        $pop->recordError('visible error');
        $output = ob_get_clean();
        self::assertStringContainsString('<pre>', $output);
        self::assertStringContainsString('visible error', $output);
    }

    public function testLoginFailsWhenNotConnected(): void
    {
        $pop = new POP3();
        self::assertFalse($pop->login('alice', 'secret'));
        self::assertSame(['Not connected to POP3 server'], $pop->getErrors());
    }

    public function testSuccessfulLoginSendsSanitizedUserAndPassCommands(): void
    {
        $pop = new POP3Scripted();
        $pop->setConnectionState(true);
        $pop->responses = ["+OK user accepted\r\n", "+OK logged in\r\n"];
        self::assertTrue($pop->login("ali\r\nce", "sec\0ret"));
        self::assertSame(["USER alice\r\n", "PASS secret\r\n"], $pop->sent);
    }

    public function testLoginFallsBackToStoredCredentialsWhenParametersAreEmpty(): void
    {
        $pop = new POP3Scripted();
        $pop->setConnectionState(true);
        $pop->username = 'stored-user';
        $pop->password = 'stored-pass';
        $pop->responses = ['+OK', '+OK'];
        self::assertTrue($pop->login('', ''));
        self::assertSame(["USER stored-user\r\n", "PASS stored-pass\r\n"], $pop->sent);
    }

    public function testLoginTreatsStringZeroAsEmptyAndUsesStoredCredentials(): void
    {
        $pop = new POP3Scripted();
        $pop->setConnectionState(true);
        $pop->username = 'fallback-user';
        $pop->password = 'fallback-pass';
        $pop->responses = ['+OK', '+OK'];
        self::assertTrue($pop->login('0', '0'));
        self::assertSame(["USER fallback-user\r\n", "PASS fallback-pass\r\n"], $pop->sent);
        // Suspicious legacy behavior: PHP empty('0') is true.
    }

    public function testRejectedUserStopsBeforeSendingPassword(): void
    {
        $pop = new POP3Scripted();
        $pop->setConnectionState(true);
        $pop->responses = ['-ERR user rejected'];
        self::assertFalse($pop->login('alice', 'secret'));
        self::assertSame(["USER alice\r\n"], $pop->sent);
        self::assertCount(1, $pop->getErrors());
    }

    public function testRejectedPasswordReturnsFalse(): void
    {
        $pop = new POP3Scripted();
        $pop->setConnectionState(true);
        $pop->responses = ['+OK user', '-ERR password rejected'];
        self::assertFalse($pop->login('alice', 'wrong'));
        self::assertSame(["USER alice\r\n", "PASS wrong\r\n"], $pop->sent);
        self::assertCount(1, $pop->getErrors());
    }

    public function testAuthoriseUsesDefaultsSanitizesInputsAndDisconnectsAfterSuccess(): void
    {
        $pop = new POP3AuthoriseDouble();
        $pop->recordError('previous error');
        $pop->connectResult = true;
        $pop->loginResult = true;
        self::assertTrue($pop->authorise('mail.example', false, false, "al\rice", "pa\nss", 2));
        self::assertSame('mail.example', $pop->host);
        self::assertSame(110, $pop->port);
        self::assertSame(30, $pop->tval);
        self::assertSame(2, $pop->do_debug);
        self::assertSame('alice', $pop->username);
        self::assertSame('pass', $pop->password);
        self::assertSame([['mail.example', 110, 30]], $pop->connections);
        self::assertSame([['alice', 'pass']], $pop->logins);
        self::assertSame(1, $pop->disconnects);
        self::assertSame([], $pop->getErrors()); // Previous errors are reset.
    }

    public function testAuthoriseCastsExplicitPortAndTimeoutAndDisconnectsOnFailedConnect(): void
    {
        $pop = new POP3AuthoriseDouble();
        $pop->connectResult = false;
        self::assertFalse($pop->authorise('localhost', '1110', '4', 'a', 'b', '1'));
        self::assertSame(1110, $pop->port);
        self::assertSame(4, $pop->tval);
        self::assertSame(1, $pop->do_debug);
        self::assertSame([], $pop->logins);
        self::assertSame(1, $pop->disconnects);
    }

    public function testAuthoriseDisconnectsIfLoginIsRejected(): void
    {
        $pop = new POP3AuthoriseDouble();
        $pop->connectResult = true;
        $pop->loginResult = false;
        self::assertFalse($pop->authorise('localhost', 110, 1, 'a', 'b'));
        self::assertSame([['a', 'b']], $pop->logins);
        self::assertSame(1, $pop->disconnects);
    }

    public function testSendStringWithoutAStreamReturnsZero(): void
    {
        $pop = new POP3Probe();
        $pop->setStream(false);
        self::assertSame(0, $pop->writeRaw("USER test\r\n"));
    }

    public function testSendStringWritesToStreamAndDebugLevelControlsOutput(): void
    {
        $stream = fopen('php://temp', 'w+');
        self::assertIsResource($stream);
        $pop = new POP3Probe();
        $pop->setStream($stream);
        $pop->do_debug = POP3::DEBUG_CLIENT;
        ob_start();
        $written = $pop->writeRaw("USER demo\r\n");
        $output = ob_get_clean();
        self::assertSame(strlen("USER demo\r\n"), $written);
        self::assertStringContainsString('Client -> Server:', $output);
        rewind($stream);
        self::assertSame("USER demo\r\n", stream_get_contents($stream));
        fclose($stream);
    }

    public function testGetResponseReadsOneLineAndDebugLevelControlsOutput(): void
    {
        $stream = fopen('php://temp', 'w+');
        fwrite($stream, "+OK example\r\n-ERR next\r\n");
        rewind($stream);
        $pop = new POP3Probe();
        $pop->setStream($stream);
        $pop->do_debug = POP3::DEBUG_SERVER;
        ob_start();
        $line = $pop->readRaw();
        $output = ob_get_clean();
        self::assertSame("+OK example\r\n", $line);
        self::assertStringContainsString('Server -> Client:', $output);
        $pop->do_debug = POP3::DEBUG_OFF;
        self::assertSame("-ERR next\r\n", $pop->readRaw());
        fclose($stream);
    }

    public function testDisconnectSendsQuitAndResetsConnectionState(): void
    {
        $stream = fopen('php://temp', 'w+');
        $pop = new POP3Probe();
        $pop->setStream($stream);
        $pop->setConnectionState(true);
        $pop->disconnect();
        self::assertFalse($pop->isConnected());
        self::assertFalse($pop->currentStream());
    }

    public function testDisconnectWithoutConnectionReturnsWithoutError(): void
    {
        $pop = new POP3Probe();
        $pop->setStream(false);
        $pop->disconnect();
        self::assertSame([], $pop->getErrors());
    }

    public function testConnectReturnsImmediatelyWhenAlreadyConnected(): void
    {
        $pop = new POP3Probe();
        $pop->setConnectionState(true);
        self::assertTrue($pop->connect('ignored.example', 1234, 1));
    }

    public function testConnectFailureLogsTheFailureWithoutExternalMailServer(): void
    {
        $pop = new POP3Probe();
        self::assertFalse($pop->connect('127.0.0.1', 0, 1));
        self::assertNotEmpty($pop->getErrors());
        self::assertStringContainsString('Failed to connect to server', implode(' ', $pop->getErrors()));
    }

    public function testConnectAcceptsPositiveGreetingFromLoopbackSocket(): void
    {
        $this->exerciseLocalGreeting('+OK ready', true);
    }

    public function testConnectRejectsNegativeGreetingFromLoopbackSocket(): void
    {
        $this->exerciseLocalGreeting('-ERR rejected', false);
    }

    private function exerciseLocalGreeting(string $greeting, bool $expected): void
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($server === false) {
            self::markTestSkipped('Local loopback sockets are not available: ' . $errstr);
        }
        $address = stream_socket_get_name($server, false);
        $port = (int) substr(strrchr($address, ':'), 1);
        $pop = new POP3GreetingDouble();
        $pop->greeting = $greeting;
        try {
            self::assertSame($expected, $pop->connect('127.0.0.1', $port, 1));
            if (!$expected) {
                self::assertNotEmpty($pop->getErrors());
            }
        } finally {
            $pop->disconnect();
            fclose($server);
        }
    }
}

class POP3Probe extends POP3
{
    public function setStream($stream): void { $this->pop_conn = $stream; }
    public function currentStream() { return $this->pop_conn; }
    public function setConnectionState(bool $state): void { $this->connected = $state; }
    public function isConnected(): bool { return $this->connected; }
    public function inspectResponse(string $value): bool { return $this->checkResponse($value); }
    public static function clean(string $value): string { return self::stripControls($value); }
    public function recordError(string $error): void { $this->setError($error); }
    public function simulateWarning(int $code, string $message, string $file, int $line): void
    { $this->catchWarning($code, $message, $file, $line); }
    public function writeRaw(string $value): int { return $this->sendString($value); }
    public function readRaw() { return $this->getResponse(); }
}

class POP3Scripted extends POP3Probe
{
    public $responses = [];
    public $sent = [];
    protected function sendString($value) { $this->sent[] = $value; return strlen($value); }
    protected function getResponse($size = 128) { return array_shift($this->responses) ?: ''; }
}

class POP3AuthoriseDouble extends POP3Probe
{
    public $connectResult = false;
    public $loginResult = false;
    public $connections = [];
    public $logins = [];
    public $disconnects = 0;
    public function connect($host, $port = false, $tval = 30)
    {
        $this->connections[] = [$host, $port, $tval];
        return $this->connectResult;
    }
    public function login($username = '', $password = '')
    {
        $this->logins[] = [$username, $password];
        return $this->loginResult;
    }
    public function disconnect() { $this->disconnects++; }
}

class POP3GreetingDouble extends POP3Probe
{
    public $greeting = '+OK';
    protected function getResponse($size = 128) { return $this->greeting; }
}
