<?php

namespace App\Extend\Apple\Result;

use http\Exception\InvalidArgumentException;

class GetUserInfoResult
{
    /**
     * @var mixed
     */
    private $_userinfo;

    /**
     * @var
     */
    private $_email;

    /**
     * @var
     */
    private $_userId;

    /**
     * @var
     */
    private $_isPrivateEmail;

    /**
     * @param array $config
     */
    public function __construct(array $token = [])
    {
        $this->_userinfo = $this->decode($token);
        $this->setUserInfo($this->_userinfo);
        $this->setEmail($this->_userinfo);
        $this->setIsPrivateEmail($this->_userinfo);
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 19:09
     * @return $this
     */
    private function setUserId()
    {
        $this->_userId = $userInfo['sub'] ?? '';
        return $this;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 19:09
     * @return mixed
     */
    public function getUserId()
    {
        return $this->_userId;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @param $userInfo
     * @return mixed
     */
    private function setUserInfo($userInfo)
    {
        $this->_userinfo = $userInfo;
        return $this;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @return mixed
     */
    public function getUserInfo()
    {
        return $this->_userinfo;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @param $userInfo
     * @return mixed
     */
    private function setEmail($userInfo)
    {
        $this->_email = $userInfo['email'] ?? '';
        return $this;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @return mixed
     */
    public function getEmail()
    {
        return $this->_email;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @param $userInfo
     * @return mixed
     */
    private function setIsPrivateEmail($userInfo)
    {
        $this->_email = $userInfo['is_private_email'] ?? '';
        return $this;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:39
     * @return mixed
     */
    public function getIsPrivateEmail()
    {
        return $this->_isPrivateEmail;
    }

    /**
     * Notes:
     * User: liushaobo
     * DateTime: 2022/5/16 18:33
     * @param array $token
     * @return mixed
     */
    private function decode(array $token = [])
    {
        $claims = explode('.', $token['id_token'])[1] ?? '';
        $claims = json_decode(base64_decode($claims), true);
        if (empty($claims)) {
            throw new InvalidArgumentException("Invalid token");
        }
        return $claims;
    }
}
