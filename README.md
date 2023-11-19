# Scaleway Container Authentication PSR-15 Middleware

> Deprecation notice : Scaleway Container Authentication has been deprecated because the authorization process is built-in now.

Private Scaleway Containers allows you to restrict access to them which prevents unauthorized access. Contrary to private functions where the authorization process is built-in, it needs to be configured inside the container. (see https://www.scaleway.com/en/docs/compute/containers/api-cli/restricting-access-to-a-container)

This PSR15 Middleware provide runtime token validation to manage authentication access to the Scaleway Container.

## Install

Via Composer

``` bash
$ composer require kdubuc/scaleway-container-auth-psr15
```

## Usage

```php
$middleware =  new ScalewayContainerAuthMiddleware([
    'auth_header_name'  => 'Scaleway-Auth-Token', // header which containing auth token (default : Scaleway-Auth-Token)
    'auth_header_regex' => ScalewayContainerAuthMiddleware::JWT_REGEX, // regex to catch token in header (default : [jwt])
    'env' => [], // to override environment variables (for testing purpose)
]);
```

## Testing

``` bash
$ vendor/bin/phpunit tests/
```

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email kevindubuc62@gmail.com instead of using the issue tracker.

## Credits

- [Kévin DUBUC](https://github.com/kdubuc)
- [All Contributors](https://github.com/kdubuc/query-string-parser/graphs/contributors)

## License

The CeCILL-B License. Please see [License File](LICENSE.md) for more information.
