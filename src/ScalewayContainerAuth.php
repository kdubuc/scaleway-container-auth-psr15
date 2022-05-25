<?php

namespace Kdubuc\Middleware;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use phpseclib3\Crypt\PublicKeyLoader;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ScalewayContainerAuth implements MiddlewareInterface
{
    public const JWT_REGEX = '/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.(?:[a-zA-Z0-9\-_]+)?$/';
    private array $options;

    /**
     * Constructor of the middleware.
     */
    public function __construct(array $custom_options = [])
    {
        $this->options = $custom_options + [
            'auth_header_name'  => 'Scaleway-Auth-Token',
            'auth_header_regex' => self::JWT_REGEX,
        ];
    }

    /**
     * Auth container routine.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface
    {
        // If container's privacy policy is set to PUBLIC (default value), ignore auth process
        $public_privacy_policy = filter_var($this->getEnv('SCW_PUBLIC') ?: true, \FILTER_VALIDATE_BOOLEAN);
        if (true === $public_privacy_policy) {
            return $handler->handle($request);
        }

        // Grab token from HTTP request usign header name & regex options
        $token = $this->grabTokenFromHttpRequest($request, $this->options['auth_header_name'], $this->options['auth_header_regex']);

        // JWT Format validation
        preg_match(self::JWT_REGEX, $token, $matches);
        if (empty($matches) || $matches[0] !== $token) {
            throw new ScalewayContainerAuthException('JWT malformed', ScalewayContainerAuthException::JWT_MALFORMED);
        }

        // Scaleway API will set PEM-encoded public Key used to decrypt tokens in environment variable
        $signature_public_key_pkcs1 = $this->getEnv('SCW_PUBLIC_KEY');
        if (null === $signature_public_key_pkcs1) {
            throw new ScalewayContainerAuthException('Public Key not found', ScalewayContainerAuthException::BAD_ENVIRONMENT_VARIABLE);
        }

        // Openssl wants the public key in X.509 style.
        // So, we use phpseclib3 to cast thePKCS#1 RSA public key into a readable one
        // Note that keys embedded within X.509 certificates will not identify themselves as X.509 - rather, they'll identify themselves as PKCS8, due to various technical reasons.
        $signature_public_key_x509 = PublicKeyLoader::load($signature_public_key_pkcs1)->toString('PKCS8');

        // Verify token (signature, aud / iat / nbf / exp / iss)
        $decoded_token = $this->validateToken($token, $signature_public_key_x509, 'SCALEWAY', 'functions');

        // Get JWT Application claim
        \assert(\array_key_exists('application_claim', $decoded_token), new ScalewayContainerAuthException('Invalid JWT claims, application_claim required', ScalewayContainerAuthException::JWT_CLAIMS_INVALID));
        \assert(\is_array($decoded_token['application_claim']) && 1 === \count($decoded_token['application_claim']), new ScalewayContainerAuthException('Invalid JWT claims, application_claim invalid', ScalewayContainerAuthException::JWT_CLAIMS_INVALID));
        $application_claim = $decoded_token['application_claim'][0];

        // Compare current Scaleway namespace id and JWT namespace_id claim
        if (property_exists($application_claim, 'namespace_id') && '' !== $application_claim->namespace_id) {
            $namespace_id = $this->getEnv('SCW_NAMESPACE_ID');
            \assert(null !== $namespace_id, new ScalewayContainerAuthException('SCW_NAMESPACE_ID is not set in environment variable', ScalewayContainerAuthException::BAD_ENVIRONMENT_VARIABLE));
            if ($namespace_id !== $application_claim->namespace_id) {
                throw new ScalewayContainerAuthException('Container Namespace invalid', ScalewayContainerAuthException::CONTAINER_NAMESPACE_MISMATCH);
            }
        }

        // Compare current Scaleway container id and JWT application_id claim (optional)
        if (property_exists($application_claim, 'application_id') && '' !== $application_claim->application_id) {
            $container_id = $this->getEnv('SCW_APPLICATION_ID');
            \assert(null !== $container_id, new ScalewayContainerAuthException('SCW_APPLICATION_ID is not set in environment variable', ScalewayContainerAuthException::BAD_ENVIRONMENT_VARIABLE));
            if ($container_id !== $application_claim->application_id) {
                throw new ScalewayContainerAuthException('Container Application invalid', ScalewayContainerAuthException::CONTAINER_APPLICATION_MISMATCH);
            }
        }

        return $handler->handle($request);
    }

    /**
     * Grab access token in server request headers.
     */
    private function grabTokenFromHttpRequest(ServerRequestInterface $server_request, string $authorization_headers_name, string $regex) : string
    {
        // Retrieve an array of all the auth header values
        $authorization_headers = $server_request->getHeader($authorization_headers_name);
        if (!\is_array($authorization_headers) || 0 === \count($authorization_headers)) {
            throw new ScalewayContainerAuthException("No $authorization_headers_name header was found", ScalewayContainerAuthException::TOKEN_HEADER_NOT_FOUND);
        }

        // Extract token from auth header using regex option
        $authorization_header = array_shift($authorization_headers);
        preg_match($regex, $authorization_header, $matches);
        if (empty($matches) || $matches[0] !== $authorization_header || 1 !== \count($matches) || empty($matches[0])) {
            throw new ScalewayContainerAuthException("No valid authorization token was found in $authorization_headers_name header", ScalewayContainerAuthException::TOKEN_NOT_FOUND);
        }

        return trim($matches[0]);
    }

    /**
     * Validate and decode JWT.
     */
    private function validateToken(string $token, string $public_key, string $issuer, string $audience) : array
    {
        // Verify the JWT and returns a decoded token
        // - Verifies presence and validity of the claims iat, nbf, and exp
        // - Check kid header to identify public key
        // - Verify the JWT signature with signing key (Only supports asymmetric algorithm RSA Signature with SHA-256)
        try {
            JWT::$leeway   = 60; // Add extra leeway time while checking nbf, iat and expiration times
            $decoded_token = (array) JWT::decode($token, new Key($public_key, 'RS256'));
        } catch (Exception $e) {
            print_r(error_get_last());
            echo openssl_error_string();
            throw new ScalewayContainerAuthException($e->getMessage(), ScalewayContainerAuthException::JWT_INVALID);
        }

        // Validation of the token issuer.
        if (!\array_key_exists('iss', $decoded_token) || $decoded_token['iss'] !== $issuer) {
            throw new ScalewayContainerAuthException("Issuer invalid (expected $issuer but received ".$decoded_token['iss'] ?? 'nothing'.')', ScalewayContainerAuthException::JWT_INVALID);
        }

        // Validation of the audience parameter on authorization calls.
        if (!\array_key_exists('aud', $decoded_token) || !\in_array($audience, (array) $decoded_token['aud'], true)) {
            throw new ScalewayContainerAuthException("Audience invalid (expected $audience but received ".$decoded_token['aud'] ?? 'nothing'.')', ScalewayContainerAuthException::JWT_INVALID);
        }

        return $decoded_token;
    }

    /**
     * First, look for value in in options array.
     * If it was not overridden, gets the value of an environment variable.
     */
    private function getEnv(string $name) : ?string
    {
        if (\array_key_exists('env', $this->options) && \array_key_exists($name, $this->options['env'])) {
            \assert(\is_string($this->options['env'][$name]));

            return $this->options['env'][$name];
        }

        $env_var = getenv($name);
        if (false !== $env_var) {
            \assert(\is_string($env_var));

            return $env_var;
        }

        return null;
    }
}
