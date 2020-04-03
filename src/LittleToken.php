<?php
namespace LittleToken;

use \Firebase\JWT\JWT;

class LittleToken
{

    public static $key    = 'lucky7';
    public static $nbf    = 3;
    public static $exp    = 1296000;
    public static $leeway = 60;

    /**
     * 签发token
     * @param $userId 用户ID
     * @param $userData 用户信息 解析token后会返回
     */
    public static function signToken($userId = '', $userData = [])
    {
        $nbf = self::$nbf;
        $exp = self::$exp;
        $key = self::$key;
        /**^_^**/
        $token = [
            'iss'  => 'auth.service',
            'aud'  => $userId,
            'iat'  => time(),
            'nbf'  => time() + $nbf,
            'exp'  => time() + $exp,
            'data' => $userData,
        ];
        $jwt = JWT::encode($token, $key);
        return $jwt;
    }

    /**
     * 解析token
     * @param $token token
     */
    public static function checkToken($token = '')
    {
        try {
            $key         = self::$key;
            JWT::$leeway = self::$leeway;
            /**^_^**/
            $deCode               = JWT::decode($token, $key, array('HS256'));
            $deCode               = (array) $deCode->data;
            $returnData['status'] = true;
            $returnData['data']   = $deCode;
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            $returnData['data']   = '签名错误';
            $returnData['status'] = false;
        } catch (\Firebase\JWT\BeforeValidException $e) {
            $returnData['data']   = '签名在某个时间点之后才能用';
            $returnData['status'] = false;
        } catch (\Firebase\JWT\ExpiredException $e) {
            $returnData['data']   = 'token已过期';
            $returnData['status'] = false;
        } catch (think\Exception $e) {
            $returnData['data']   = '其它错误';
            $returnData['status'] = false;
        }
        return $returnData;
    }
}
