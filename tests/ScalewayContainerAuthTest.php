<?php

use Firebase\JWT\JWT;
use phpseclib3\Crypt\RSA;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Message\ResponseInterface;
use Kdubuc\Middleware\ScalewayContainerAuth;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kdubuc\Middleware\ScalewayContainerAuthException;

class ScalewayContainerAuthTest extends TestCase
{
    protected static string $private_key;
    protected static string $public_key;

    public static function setUpBeforeClass() : void
    {
        $private_key = RSA::createKey();
        $public_key  = $private_key->getPublicKey();

        self::$private_key = $private_key->toString('PKCS1');
        self::$public_key  = $public_key->toString('PKCS1');
    }

    private function processScalewayContainerAuthMiddleware(array $options = [], ServerRequestInterface $server_request = null) : ResponseInterface
    {
        // Request Handler (always return a new response)
        $handler_stub = $this->createStub(RequestHandlerInterface::class);
        $handler_stub->method('handle')->willReturn(new Response());

        $middleware = new ScalewayContainerAuth($options);

        if (null === $server_request) {
            $server_request = (new HttpFactory())->createServerRequest('GET', '/');
        }

        return $middleware->process($server_request, $handler_stub);
    }

    private function generateScalewayJWT(string $namespace_id, string $application_id = '') : string
    {
        return JWT::encode([
            'iss'               => 'SCALEWAY',
            'aud'               => 'functions',
            'application_claim' => [
                [
                    'namespace_id'   => $namespace_id,
                    'application_id' => $application_id,
                ],
            ],
        ], self::$private_key, 'RS256');
    }

    public function testPublicAccess()
    {
        $response = $this->processScalewayContainerAuthMiddleware();

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    public function testPrivateAccessWithoutAuthHeader()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::TOKEN_HEADER_NOT_FOUND);

        $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC' => 'false',
            ],
        ]);
    }

    public function testPrivateAccessWithAuthHeaderAndEmptyToken()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::TOKEN_NOT_FOUND);

        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', '');

        $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC' => 'false',
            ],
        ], $server_request);
    }

    public function testPrivateAccessWithCustomRegexAndBadJwt()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::JWT_MALFORMED);

        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', 'xx');

        $this->processScalewayContainerAuthMiddleware([
            'auth_header_regex' => '/^.*$/',
            'env'               => [
                'SCW_PUBLIC' => 'false',
            ],
        ], $server_request);
    }

    public function testPrivateAccessWithoutPublicKeyInEnv()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::BAD_ENVIRONMENT_VARIABLE);

        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', $this->generateScalewayJWT('test'));

        $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC' => 'false',
            ],
        ], $server_request);
    }

    public function testPrivateNamespaceUnauthorizedAccess()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::CONTAINER_NAMESPACE_MISMATCH);

        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', $this->generateScalewayJWT('test'));

        $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC'       => 'false',
                'SCW_PUBLIC_KEY'   => self::$public_key,
                'SCW_NAMESPACE_ID' => 'bad_namespace',
            ],
        ], $server_request);
    }

    public function testPrivateNamespaceAccess()
    {
        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', $this->generateScalewayJWT('test'));

        $response = $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC'       => 'false',
                'SCW_PUBLIC_KEY'   => self::$public_key,
                'SCW_NAMESPACE_ID' => 'test',
            ],
        ], $server_request);

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    public function testPrivateNamespaceAndContainerAccess()
    {
        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', $this->generateScalewayJWT('test', 'container'));

        $response = $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC'         => 'false',
                'SCW_PUBLIC_KEY'     => self::$public_key,
                'SCW_NAMESPACE_ID'   => 'test',
                'SCW_APPLICATION_ID' => 'container',
            ],
        ], $server_request);

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    public function testPrivateContainerUnauthorizedAccess()
    {
        $this->expectException(ScalewayContainerAuthException::class);
        $this->expectExceptionCode(ScalewayContainerAuthException::CONTAINER_APPLICATION_MISMATCH);

        $server_request = (new HttpFactory())->createServerRequest('GET', '/')->withAddedHeader('Scaleway-Auth-Token', $this->generateScalewayJWT('test', 'bad_container'));

        $this->processScalewayContainerAuthMiddleware([
            'env' => [
                'SCW_PUBLIC'         => 'false',
                'SCW_PUBLIC_KEY'     => self::$public_key,
                'SCW_NAMESPACE_ID'   => 'test',
                'SCW_APPLICATION_ID' => 's',
            ],
        ], $server_request);
    }
}
