<?php

namespace app\controllers;

use app\models\Account;
use Yii;
use yii\web\Controller;
use yii\web\Cookie;

/*
 * 公共方法模块
 * @author zhaiyu
 * @date 20160308
 */

class CommonController extends Controller
{
    /**
     * post请求--普通请求
     * @param $url
     * @param $data
     * @return array
     */
    protected function Sim_HttpPost($url, $data)
    {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        return $this->Sim_HttpRequest($url, $data, $headers);
    }

    /**
     * post请求--网易云信专用请求
     * @param $url
     * @param $data
     * @return array
     */
    protected function Net_HttpPost($url, $data)
    {
        $appToken = Yii::$app->params['appToken'];
        $appSecret = $appToken['appSecret'];
        $nonce = $this->RandStrCode(32);//随机字符串
        $curTime = time();
        $checkSum = sha1($appSecret.$nonce.$curTime);//加密字符串
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded;charset=utf-8',
            'AppKey'=>$appToken['AppKey'],
            'Nonce'=>$nonce,
            'CurTime'=>$curTime,
            'CheckSum'=>$checkSum,
        ];
        return $this->Sim_HttpRequest($url, $data, $headers);
    }

    /**
     * 模拟接口请求常用方法--Sim_HttpRequest(模拟get请求)
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param $url
     * @param string $post
     * @param array $extra
     * @param int $timeout
     * @return array
     */
    protected function Sim_HttpRequest($url, $post = '', $extra = array(), $timeout = 60)
    {
        $urlset = parse_url($url);
        if (empty($urlset['path'])) {
            $urlset['path'] = '/';
        }
        if (!empty($urlset['query'])) {
            $urlset['query'] = '?'.$urlset['query'];
        }else{
            $urlset['query'] = '';
        }
        if (empty($urlset['port'])) {
            $urlset['port'] = $urlset['scheme'] == 'https' ? '443' : '80';
        }
        if ($this->StrExists($url, 'https://') && !extension_loaded('openssl')) {
            if (!extension_loaded("openssl")) {
                exit('请开启您PHP环境的openssl');
            }
        }
        if (function_exists('curl_init') && function_exists('curl_exec')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $urlset['scheme'] . '://' . $urlset['host'] . ($urlset['port'] == '80' ? '' : ':' . $urlset['port']) . $urlset['path'] . $urlset['query']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 1);
            if ($post) {
                curl_setopt($ch, CURLOPT_POST, 1);
                if (is_array($post)) {
                    $post = http_build_query($post);
                }
                curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
            }
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSLVERSION, 4);
            curl_setopt($ch, CURLOPT_REFERER, 'http://' . $_SERVER['HTTP_HOST']);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0.1) Gecko/20100101 Firefox/9.0.1');
            if(defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) {
                curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            }
            if (!empty($extra) && is_array($extra)) {
                $headers = array();
                foreach ($extra as $opt => $value) {
                    if ($this->StrExists($opt, 'CURLOPT_')) {
                        curl_setopt($ch, constant($opt), $value);
                    } elseif (is_numeric($opt)) {
                        curl_setopt($ch, $opt, $value);
                    } else {
                        $headers[] = "{$opt}: {$value}";
                    }
                }
                if (!empty($headers)) {
                    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                }
            }
            $data = curl_exec($ch);
            $errno = curl_errno($ch);
            $error = curl_error($ch);
            curl_close($ch);
            if ($errno || empty($data)) {
                return array(
                    'code' => 5300,
                    'msg' => $error,
                );
            } else {
                $result = $this->Sim_HttpResponseParse($data);
                if($result['code'] == 200){
                    return json_decode($result['content'], true);
                }else{
                    return array(
                        'code' => 5300,
                        'msg' => 'server error',
                    );
                }
            }
        }
        $method = empty($post) ? 'GET' : 'POST';
        $fdata = "{$method} {$urlset['path']}{$urlset['query']} HTTP/1.1\r\n";
        $fdata .= "Host: {$urlset['host']}\r\n";
        if (function_exists('gzdecode')) {
            $fdata .= "Accept-Encoding: gzip, deflate\r\n";
        }
        $fdata .= "Connection: close\r\n";
        if (!empty($extra) && is_array($extra)) {
            foreach ($extra as $opt => $value) {
                if (!$this->StrExists($opt, 'CURLOPT_')) {
                    $fdata .= "{$opt}: {$value}\r\n";
                }
            }
        }
        if ($post) {
            if (is_array($post)) {
                $body = http_build_query($post);
            } else {
                $body = urlencode($post);
            }
            $fdata .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
        } else {
            $fdata .= "\r\n";
        }
        if ($urlset['scheme'] == 'https') {
            $fp = fsockopen('ssl://' . $urlset['host'], $urlset['port'], $errno, $error);
        } else {
            $fp = fsockopen($urlset['host'], $urlset['port'], $errno, $error);
        }
        stream_set_blocking($fp, true);
        stream_set_timeout($fp, $timeout);
        if (!$fp) {
            return array(
                'code' => 5300,
                'msg' => $error,
            );
        } else {
            fwrite($fp, $fdata);
            $content = '';
            while (!feof($fp))
                $content .= fgets($fp, 512);
            fclose($fp);
            $result = $this->Sim_HttpResponseParse($content, true);
            if($result['code'] == 200){
                return json_decode($result['content'], true);
            }else{
                return array(
                    'code' => 5300,
                    'msg' => 'server error',
                );
            }
        }
    }

    private function Sim_HttpResponseParse($data, $chunked = false)
    {
        $rlt = array();
        $pos = strpos($data, "\r\n\r\n");
        $split1[0] = substr($data, 0, $pos);
        $split1[1] = substr($data, $pos + 4, strlen($data));
        $split2 = explode("\r\n", $split1[0], 2);
        preg_match('/^(\S+) (\S+) (\S+)$/', $split2[0], $matches);
        $rlt['code'] = $matches[2];
        $rlt['status'] = $matches[3];
        $rlt['responseline'] = $split2[0];
        $header = explode("\r\n", $split2[1]);
        $isgzip = false;
        $ischunk = false;
        foreach ($header as $v) {
            $row = explode(':', $v);
            $key = trim($row[0]);
            $value = trim($row[1]);
            $rlt['headers'][$key] = $value;
            if (!$isgzip && strtolower($key) == 'content-encoding' && strtolower($value) == 'gzip') {
                $isgzip = true;
            }
            if (!$ischunk && strtolower($key) == 'transfer-encoding' && strtolower($value) == 'chunked') {
                $ischunk = true;
            }
        }
        if ($chunked && $ischunk) {
            $rlt['content'] = $this->Sim_HttpResponseParseUnChunk($split1[1]);
        } else {
            $rlt['content'] = $split1[1];
        }
        if ($isgzip && function_exists('gzdecode')) {
            $rlt['content'] = gzdecode($rlt['content']);
        }
        $rlt['meta'] = $data;
        if ($rlt['code'] == '100') {
            return $this->Sim_HttpResponseParse($rlt['content']);
        }
        return $rlt;
    }

    private function Sim_HttpResponseParseUnChunk($str = null)
    {
        if (!is_string($str) or strlen($str) < 1) {
            return false;
        }
        $eol = "\r\n";
        $add = strlen($eol);
        $tmp = $str;
        $str = '';
        do {
            $tmp = ltrim($tmp);
            $pos = strpos($tmp, $eol);
            if ($pos === false) {
                return false;
            }
            $len = hexdec(substr($tmp, 0, $pos));
            if (!is_numeric($len) or $len < 0) {
                return false;
            }
            $str .= substr($tmp, ($pos + $add), $len);
            $tmp = substr($tmp, ($len + $pos + $add));
            $check = trim($tmp);
        } while (!empty($check));
        unset($tmp);
        return $str;
    }

    /**
     * $string字符串中是否包含$find字符串
     * @param $string
     * @param $find
     * @return bool
     */
    protected function StrExists($string, $find)
    {
        return !(strpos($string, $find) === FALSE);
    }

    /**
     * 生成随机字符串
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param int $length
     * @return string
     */
    protected function RandStrCode($length = 8)
    {
        // 密码字符集，可任意添加你需要的字符
        $chars = '2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY';
        $str = '';
        for ($i = 0; $i < $length; $i++) {
            // 这里提供两种字符获取方式
            // 第一种是使用 substr 截取$chars中的任意一位字符；
            // 第二种是取字符数组 $chars 的任意元素
            // $str .= substr($chars, mt_rand(0, strlen($chars) – 1), 1);
            $str .= $chars[mt_rand(0, strlen($chars) - 1)];
        }
        return $str;
    }

    /**
     * DZ自带加密
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param $string
     * @param string $operation
     * @param string $key
     * @param int $expiry
     * @return string
     */
    protected function AuthCode($string, $operation = 'DECODE', $key, $expiry = 0)
    {
        $ckey_length = 4;
        $key = md5($key);
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';
        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);
        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);
        $result = '';
        $box = range(0, 255);
        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 'DECODE') {
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            return $keyc . str_replace('=', '', base64_encode($result));
        }
    }

    /**
     * 检测手机号有效性(中国大陆)
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param $phone
     * @return bool
     */
    protected function CheckPhoneValidate($phone)
    {
        return preg_match('/^1[3578]\d{9}$/', $phone);
    }

    /** 检测邮箱有效性
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param $email
     * @return bool
     */
    protected function CheckEmailValidate($email)
    {
        return preg_match('/^[a-zA-Z0-9][\w-\.]+@[\w-]+\.[\w-\.]+$/', $email);
    }

    /**
     * 系统手机发送短信函数
     * @author zhaiyu
     * @startDate 2015-10-12
     * @upDate 2015-10-12
     * @param string $mobile 接收短信者手机
     * @param string $content 短信内容
     * @return array
     */
    protected function SendMessage($mobile, $content)
    {
        $url = 'http://sdk2.entinfo.cn/z_send.aspx';
        $sn = 'SDK-HZK-010-00003';
        $password = '943586';
        $data['sn'] = $sn;
        $data['pwd'] = $password;
        $data['mobile'] = $mobile;
        $data['content'] = iconv('UTF-8', 'GB2312', $content . '[亿房网]');
        $str = $this->Sim_HttpPost($url, $data);
        switch ($str['content']) {
            case 1:
                return array('status' => 1, 'msg' => '发送成功');
            case -1:
                return array('status' => -1, 'msg' => '发送失败');
            case -2:
                return array('status' => -2, 'msg' => '参数错误');
            case -3:
                return array('status' => -3, 'msg' => '短信帐号密码不正确');
            default:
                return array('status' => 0, 'msg' => '未知错误');
        }
    }

    /**
     * Ajax方式返回数据到客户端
     * @author zhaiyu
     * @startDate 20160310
     * @upDate 20160310
     * @param array $content 要返回的数据
     * @param String $method
     * @param String $type AJAX返回数据格式
     * @param String $handler 默认的JSONP格式返回的处理方法是callback
     * @return void
     */
    protected function ajaxReturn($content = [], $method = '', $type = 'JSON', $handler = 'callback') {
        if(in_array(200,$content) || in_array(201, $content)){
            $methodArr = array_pad(explode('.',$method), -3, '');
            $response = $methodArr[1].'_'.$methodArr[2].'_response';
            $format = ['code', 'msg', 'data', 'extend'];
        }else{
            $response = 'error_response';
            $format = ['code', 'msg','sub_code','sub_msg'];
        }
        $result = array_combine($format, array_pad($content, 4, ''));
        $data = [$response => $result];
        switch (strtoupper($type)) {
            case 'JSON':
                // 返回JSON数据格式到客户端 包含状态信息
                header('Content-Type:application/json; charset=utf-8');
                $data = json_encode($data);
                break;
            case 'JSONP':
                // 返回JSON数据格式到客户端 包含状态信息
                header('Content-Type:application/json; charset=utf-8');
                $data = $handler . '(' . json_encode($data) . ');';
                break;
            case 'EVAL':
                // 返回可执行的js脚本
                header('Content-Type:text/html; charset=utf-8');
                break;
        }
        exit($data);
    }


    /**
     * 设置cookie值
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array $cookieArr
     * @param int $expire
     * @param null $domain
     * @param bool $httpOnly
     */
    protected function setCookieCode($cookieArr = [], $expire = 0, $domain = null, $httpOnly = false){
        $cookie = Yii::$app->response->cookies;
        if(is_array($cookieArr)){
            foreach($cookieArr as $key => $val){
                $cookie->add(new Cookie([
                    'name' => $key,
                    'value' => $val,
                    'expire' => $expire,
                    'domain' => $domain,
                    'httpOnly' => $httpOnly,
                ]));
            }
        }
    }

    /**
     * 删除cookie值
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array|string $keys
     */
    protected function rmCookieCode($keys = []){
        $cookie = Yii::$app->response->cookies;
        if(empty($keys)){
            $cookie->removeAll();
        }elseif(is_array($keys)){
            foreach($keys as $val){
                $cookie->remove($val);
            }
        }else{
            $cookie->remove($keys);
        }
    }

    /**
     * 获取cookie值
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array|string $keys
     * @return array
     */
    protected function getCookieCode($keys){
        $return = [];
        $cookie = Yii::$app->request->cookies;
        if(is_array($keys)){
            foreach($keys as $val){
                $return[$val] = $cookie->getValue($val);
            }
        }else{
            $return[$keys] = $cookie->getValue($keys);
        }
        return $return;
    }

    /**
     * 公共域cookie操作
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param $key
     * @param string $val
     * @return bool
     */
    protected function comCookie($key, $val = ''){
        $cookieDomain = $this->getParams('cookieSet');
        if(is_null($val)){
            //清除cookie
            $return = setcookie($key, '', null, $cookieDomain['path'], $cookieDomain['domain']);
        }elseif('' == $val){
            // 获取cookie
            if(isset($_COOKIE[$key])){
                $return = $_COOKIE[$key];
            }else{
                $return = null;
            }
        }else{
            //设置cookie
            $return = setcookie($key, $val, null, $cookieDomain['path'], $cookieDomain['domain']);
        }
        return $return;
    }
    /**
     * 获取配置值
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param string $key
     * @return array
     */
    protected function getParams($key = ''){
        $return = Yii::$app->params;
        if($key){
            $return = $return[$key];
        }
        return $return;
    }

    /**
     * 获取post和get请求
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param string $type
     * @return array|mixed
     */
    protected function getRequest($type = 'get'){
        $return = [];
        switch($type){
            case 'get':$return = Yii::$app->request->get();break;
            case 'post':$return = Yii::$app->request->post();break;
        }
        return $return;
    }

    /**
     * 验证登录状态
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @return array|bool
     */
    protected function checkLogin(){
        $return = [];
        /*$return['ucToken'] = $this->comCookie('uc_token');
        $return['userId'] = $this->comCookie('uc_userInfo');*/
        $request = $this->getRequest();
        $return['ucToken'] = $request['uc_token'];
        $return['userId'] = $request['uc_userInfo'];
        if($return['ucToken'] && $return['userId']){
            $imToken = $this->comCookie('im_token');
            if(empty($imToken)){
                $account = (new Account())->getOne(['userId' => $return['userId']]);
                if($account) {
                    $this->comCookie('im_token', $account['password']);
                }
            }
            return $return;
        }else{
            return false;
        }
    }

    /**
     * 设置缓存
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array $cacheArr
     * @param int $expire
     */
    protected function setCache($cacheArr = [], $expire = 0){
        $cache = Yii::$app->cache;
        $cacheSet = $this->getParams('cacheSet');
        if(is_array($cacheArr)){
            foreach($cacheArr as $key => $val){
                $cache->set($cacheSet['prefix'].$key, $val, $expire);
            }
        }
    }

    /**
     * 获取缓存
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array|string $keys
     * @return array
     */
    protected function getCache($keys){
        $cache = Yii::$app->cache;
        $cacheSet = $this->getParams('cacheSet');
        $return = [];
        if(is_array($keys)){
            foreach($keys as $val){
                $return[$val] = $cache->get($cacheSet['prefix'].$val);
            }
        }else{
            $return[$keys] = $cache->get($cacheSet['prefix'].$keys);
        }
        return $return;
    }

    /**
     * 删除缓存
     * @author zhaiyu
     * @startDate 20160316
     * @upDate 20160316
     * @param array|string $keys
     */
    protected function rmCache($keys = ''){
        $cache = Yii::$app->cache;
        if(empty($keys)){
            $cache->flush();
        }elseif(is_array($keys)){
            foreach($keys as $val){
                $cache->delete($val);
            }
        }else{
            $cache->delete($keys);
        }
    }
}
