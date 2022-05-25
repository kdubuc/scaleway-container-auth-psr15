<?php

namespace Kdubuc\Middleware;

use Exception;

final class ScalewayContainerAuthException extends Exception
{
    public const JWT_MALFORMED                  = 1;
    public const TOKEN_HEADER_NOT_FOUND         = 2;
    public const TOKEN_NOT_FOUND                = 3;
    public const JWT_INVALID                    = 4;
    public const JWT_CLAIMS_INVALID             = 5;
    public const CONTAINER_NAMESPACE_MISMATCH   = 6;
    public const CONTAINER_APPLICATION_MISMATCH = 7;
    public const BAD_ENVIRONMENT_VARIABLE       = 8;
}
