<?php
namespace App\Extend\Apple\Http;



use App\Extend\Apple\Request\HttpHandler\HttpClientCache;
use App\Extend\Apple\Request\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Utils;
use http\Exception\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class OAuth2
{

    /**
     * The current grant type.
     *
     * @var string
     */
    private $grantType;

    /**
     * The authorization code issued to this client.
     *
     * Only used by the authorization code access grant type.
     *
     * @var string
     */
    private $code;

    /**
     * A unique identifier issued to the client to identify itself to the
     * authorization server.
     *
     * @var string
     */
    private $clientId;

    /**
     * A shared symmetric secret issued by the authorization server, which is
     * used to authenticate the client.
     *
     * @var string
     */
    private $clientSecret;
    /**
     * The redirection URI used in the initial request.
     *
     * @var string
     */
    private $redirectUri;


    /**
     * @var array $config
     */
    private $config;

    /**
     * The well known grant types.
     *
     * @var array
     */
    public static $knownGrantTypes = array(
        'authorization_code',
    );
    /**
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;

        $this->setClientId($this->config['clientId']);
        $this->setRedirectUri($this->config['redirectUri']);
        $this->setTokenCredentialUri($this->config['tokenCredentialUri']);
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 15:33
     * @param callable|null $httpHandler
     * @return array
     * @throws \Exception
     */
    function fetchAuthToken(callable $httpHandler = null)
    {
        if (is_null($httpHandler)) {
            $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        }

        $response = $httpHandler($this->generateCredentialsRequest());
        $credentials = $this->parseTokenResponse($response);
        return $credentials;
    }

    /**
     * Gets the authorization code issued to this client.
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * Sets the authorization code issued to this client.
     *
     * @param string $code
     */
    public function setCode($code)
    {
        $this->code = $code;
    }

    /**
     * Gets the redirection URI used in the initial request.
     *
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Sets the redirection URI used in the initial request.
     *
     * @param string $uri
     */
    public function setRedirectUri($uri)
    {
        if (is_null($uri)) {
            $this->redirectUri = null;

            return;
        }
        // redirect URI must be absolute
        if (!$this->isAbsoluteUri($uri)) {
            // "postmessage" is a reserved URI string in Google-land
            // @see https://developers.google.com/identity/sign-in/web/server-side-flow
            if ('postmessage' !== (string)$uri) {
                throw new InvalidArgumentException(
                    'Redirect URI must be absolute'
                );
            }
        }
        $this->redirectUri = (string)$uri;
    }

    /**
     * Generates a request for token credentials.
     *
     * @return RequestInterface the authorization Url.
     */
    public function generateCredentialsRequest()
    {
        $uri = $this->getTokenCredentialUri();
        if (is_null($uri)) {
            throw new \DomainException('No token credential URI was set.');
        }

        $grantType = $this->getGrantType();
        $params = array('grant_type' => $grantType);
        switch ($grantType) {
            case 'authorization_code':
                $params['code'] = $this->getCode();
                $params['redirect_uri'] = $this->getRedirectUri();
                $this->addClientCredentials($params);
                break;
            default:
                if (!is_null($this->getRedirectUri())) {
                    # Grant type was supposed to be 'authorization_code', as there
                    # is a redirect URI.
                    throw new \DomainException('Missing authorization code');
                }
                unset($params['grant_type']);
                if (!is_null($grantType)) {
                    $params['grant_type'] = $grantType;
                }
        }

        $headers = [
            'Cache-Control' => 'no-store',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];
        return new Request(
            'POST',
            $uri,
            $headers,
            Query::build($params)
        );
    }

    /**
     * Sets a unique identifier issued to the client to identify itself to the
     * authorization server.
     */
    public function getClientId()
    {
        return $this->clientId;
    }
    /**
     * Sets a unique identifier issued to the client to identify itself to the
     * authorization server.
     *
     * @param $clientId
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
    }
    /**
     * @param array $params
     * @return array
     */
    private function addClientCredentials(&$params)
    {
        $clientId = $this->getClientId();
        $clientSecret = $this->getClientSecret(
            '',
            '',
            $clientId,
            file_get_contents('../app/Extend/Apple/Cert/AuthKey_FXY3M4LST7.p8')
        );
        if ($clientId && $clientSecret) {
            $params['client_id'] = $clientId;
            $params['client_secret'] = $clientSecret;
        }

        return $params;
    }

    public function getClientSecret($kid, $iss, $sub, $key)
    {
        if (class_exists('Firebase\JWT\JWT')) {
            return \Firebase\JWT\JWT::encode([
                'iss' => $iss,
                'iat' => time(),
                'exp' => time() + 3600,
                'aud' => 'https://appleid.apple.com',
                'sub' => $sub
            ], $key, 'ES256', $kid);
        }
        return \JWT::encode([
            'iss' => $iss,
            'iat' => time(),
            'exp' => time() + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $sub
        ], $key, 'ES256', $kid);

    }


    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 15:47
     * @param $kid
     * @param $iss
     * @param $sub
     * @param $key
     * @return false|string
     */
    private function generateJWT($kid, $iss, $sub, $key)
    {
        $header = [
            'alg' => 'ES256',
            'kid' => $kid
        ];

        $body = [
            'iss' => $iss,
            'iat' => time(),
            'exp' => time() + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $sub
        ];

        $privateKey = openssl_pkey_get_private($key);
        if (!$privateKey) return false;

        $payload = $this->encode(json_encode($header)).'.' . $this->encode(json_encode($body));
        $signature = '';
        $success = openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        if (!$success) return false;
        return $payload . '.' . $this->encode($signature);
    }


    /**
     * Gets the current grant type.
     *
     * @return string
     */
    public function getGrantType()
    {
        if (!is_null($this->grantType)) {
            return $this->grantType;
        }
        // Returns the inferred grant type, based on the current object instance
        // state.
        if (!is_null($this->code)) {
            return 'authorization_code';
        }
        return null;
    }

    /**
     * Sets the current grant type.
     *
     * @param $grantType
     * @throws InvalidArgumentException
     */
    public function setGrantType($grantType)
    {
        if (in_array($grantType, self::$knownGrantTypes)) {
            $this->grantType = $grantType;
        } else {
            // validate URI
            if (!$this->isAbsoluteUri($grantType)) {
                throw new InvalidArgumentException(
                    'invalid grant type'
                );
            }
            $this->grantType = (string)$grantType;
        }
    }
    /**
     * Gets the authorization server's HTTP endpoint capable of issuing tokens
     * and refreshing expired tokens.
     *
     * @return string
     */
    public function getTokenCredentialUri()
    {
        return $this->tokenCredentialUri;
    }

    /**
     * Sets the authorization server's HTTP endpoint capable of issuing tokens
     * and refreshing expired tokens.
     *
     * @param string $uri
     */
    public function setTokenCredentialUri($uri)
    {
        $this->tokenCredentialUri = $this->coerceUri($uri);
    }

    /**
     * Parses the fetched tokens.
     *
     * @param ResponseInterface $resp the response.
     * @return array the tokens parsed from the response body.
     * @throws \Exception
     */
    public function parseTokenResponse(ResponseInterface $resp)
    {
        $body = (string)$resp->getBody();

        if ($resp->hasHeader('Content-Type') &&
            $resp->getHeaderLine('Content-Type') == 'application/x-www-form-urlencoded'
        ) {
            $res = array();
            parse_str($body, $res);

            return $res;
        }

        // Assume it's JSON; if it's not throw an exception
        if (null === $res = json_decode($body, true)) {
            throw new \Exception('Invalid JSON response');
        }
        return $res;
    }

    /**
     * Determines if the URI is absolute based on its scheme and host or path
     * (RFC 3986).
     *
     * @param string $uri
     * @return bool
     */
    private function isAbsoluteUri($uri)
    {
        $uri = $this->coerceUri($uri);

        return $uri->getScheme() && ($uri->getHost() || $uri->getPath());
    }

    /**
     * @todo handle uri as array
     *
     * @param string $uri
     * @return null|UriInterface
     */
    private function coerceUri($uri)
    {
        if (is_null($uri)) {
            return;
        }

        return Utils::uriFor($uri);
    }
}
