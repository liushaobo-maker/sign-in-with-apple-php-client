<?php
/**
 * 创建人: liushaobo
 * 日期: 2022/5/16
 * 描述:
 */

namespace App\Extend\Apple;


use App\Extend\Apple\Http\OAuth2;
use App\Extend\Apple\Request\HttpHandler\HttpHandlerFactory;
use App\Extend\Apple\Result\GetUserInfoResult;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use http\Exception\InvalidArgumentException;

class AppleClient
{
    const CLIENT_ID_ENV_NAME    = 'APPLE_CLIENT_ID';
    const REDIRECT_URI_ENV_NAME = 'APPLE_REDIRECT_URI';
    const OAUTH2_TOKEN_URI      = 'https://appleid.apple.com/auth/token';

    /**
     * @var array access token
     */
    private $token;

    /**
     * @var array $config
     */
    private $config;

    /**
     * @var
     */
    private $auth;

    /**
     * @var ClientInterface $http
     */
    private $http;

    /**
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'client_id' => getenv(static::CLIENT_ID_ENV_NAME),
            'redirect_uri' => getenv(static::REDIRECT_URI_ENV_NAME),
        ], $config);
    }

    /**
     * Notes:liushaobo
     * User: liushaobo
     * DateTime: 2022/5/16 16:48
     * @param $code
     * @return array
     * @throws \Exception
     */
    public function fetchAccessToken($code)
    {
        if (strlen($code) == 0) {
            throw new InvalidArgumentException("Invalid code");
        }
        $auth = $this->getOAuth2Service();
        $auth->setCode($code);
        $auth->setRedirectUri($this->getRedirectUri());
        $httpHandler = HttpHandlerFactory::build($this->getHttpClient());
        $creds = $auth->fetchAuthToken($httpHandler);
        if ($creds && isset($creds['access_token'])) {
            $creds['created'] = time();
            $this->setAccessToken($creds);
        }

        return $creds;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:59
     * @return GetUserInfoResult
     */
    public function getUser()
    {
        if (!isset($this->getUserInfo)) {
            $this->getUserInfo = $this->createGetUserInfoResult();
        }

        return $this->getUserInfo;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:58
     * @return GetUserInfoResult
     */
    public function createGetUserInfoResult()
    {
        $userinfo = new GetUserInfoResult($this->getAccessToken());
        return $userinfo;
    }

    public function getOAuth2Service()
    {
        if (!isset($this->auth)) {
            $this->auth = $this->createOAuth2Service();
        }

        return $this->auth;
    }

    /**
     * Set the OAuth 2.0 Client ID.
     * @param string $clientId
     */
    public function setClientId($clientId)
    {
        $this->config['client_id'] = $clientId;
    }

    public function getClientId()
    {
        return $this->config['client_id'];
    }

    /**
     * Set the OAuth 2.0 Redirect URI.
     * @param string $redirectUri
     */
    public function setRedirectUri($redirectUri)
    {
        $this->config['redirect_uri'] = $redirectUri;
    }

    public function getRedirectUri()
    {
        return $this->config['redirect_uri'];
    }

    /**
     * create a default google auth object
     */
    protected function createOAuth2Service()
    {
        $auth = new OAuth2([
                'clientId'              => $this->getClientId(),
                'grantType'             => 'authorization_code',
                'tokenCredentialUri'    => self::OAUTH2_TOKEN_URI,
                'redirectUri'           => $this->getRedirectUri(),
        ]);

        return $auth;
    }

    /**
     * @return ClientInterface
     */
    public function getHttpClient()
    {
        if (null === $this->http) {
            $this->http = $this->createDefaultHttpClient();
        }

        return $this->http;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 15:08
     * @return GuzzleClient
     */
    protected function createDefaultHttpClient()
    {
        $guzzleVersion = null;
        if (defined('\GuzzleHttp\ClientInterface::MAJOR_VERSION')) {
            $guzzleVersion = ClientInterface::MAJOR_VERSION;
        } elseif (defined('\GuzzleHttp\ClientInterface::VERSION')) {
            $guzzleVersion = (int)substr(ClientInterface::VERSION, 0, 1);
        }
        if (5 === $guzzleVersion) {
            $options = [];
        } elseif (6 === $guzzleVersion || 7 === $guzzleVersion) {
            // guzzle 6 or 7
            $options = [];
        } else {
            throw new \LogicException('Could not find supported version of Guzzle.');
        }
        return new GuzzleClient($options);
    }


    /**
     * Set the access token used for requests.
     * @param string|array $token
     * @throws InvalidArgumentException
     */
    public function setAccessToken($token)
    {
        if (is_string($token)) {
            if ($json = json_decode($token, true)) {
                $token = $json;
            } else {
                // assume $token is just the token string
                $token = array(
                    'access_token' => $token,
                );
            }
        }
        if ($token == null) {
            throw new InvalidArgumentException('invalid json token');
        }
        if (!isset($token['access_token'])) {
            throw new InvalidArgumentException("Invalid token format");
        }
        $this->token = $token;
    }


    public function getAccessToken()
    {
        return $this->token;
    }

}
