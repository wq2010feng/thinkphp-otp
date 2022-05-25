<?php
/*
+----------------------------------------------------------------------
| ThinkPHP 6 OTP ,用于处理Google Authenticator 2因素身份验证的PHP类。
+----------------------------------------------------------------------
| Copyright (c) 2022 Keefe rights reserved.
+----------------------------------------------------------------------
| Licensed ( http://www.apache.org/licenses/LICENSE-2.0 ;)
+----------------------------------------------------------------------
| Author: keefe <wq2010feng@126.com>
+----------------------------------------------------------------------
*/
namespace think\keefe;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\ErrorCorrectionLevel\ErrorCorrectionLevelLow;
use Endroid\QrCode\ErrorCorrectionLevel\ErrorCorrectionLevelMedium;
use Endroid\QrCode\ErrorCorrectionLevel\ErrorCorrectionLevelQuartile;
use Endroid\QrCode\ErrorCorrectionLevel\ErrorCorrectionLevelHigh;

class Otp
{
    protected $_codeLength = 6;
    /**
     * 创建一份密钥
     * 16个字符，从允许的32个字符中随机选择。
     * @param int $secret_length
     * @return string
     */
    public function createSecret($secret_length = 16)
    {
        $valid_chars = $this->_getBase32LookupTable();
        // 有效的秘密长度为80到640位
        if ($secret_length < 16 || $secret_length > 128) {
            throw new \Exception('错误的密钥长度，Bad secret length');
        }
        $secret = '';
        $rnd = false;
        if (function_exists('random_bytes')) {
            $rnd = random_bytes($secret_length);
        } elseif (function_exists('mcrypt_create_iv')) {
            $rnd = mcrypt_create_iv($secret_length, MCRYPT_DEV_URANDOM);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $rnd = openssl_random_pseudo_bytes($secret_length, $crypto_strong);
            if (!$crypto_strong) {
                $rnd = false;
            }
        }
        if ($rnd !== false) {
            for ($i = 0; $i < $secret_length; ++$i) {
                $secret .= $valid_chars[ord($rnd[$i]) & 31];
            }
        } else {
            throw new \Exception('没有安全的随机数据源，No source of secure random');
        }
        return $secret;
    }
    /**
     * 用给定的密码和时间点计算验证码
     *
     * @param string   $secret
     * @param int|null $time_slice
     *
     * @return string
     */
    public function getCode($secret, $time_slice = null)
    {
        if ($time_slice === null) {
            $time_slice = floor(time() / 30);
        }

        $secretkey = $this->_base32Decode($secret);

        // 将时间打包成二进制字符串
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $time_slice);
        // 用用户密钥散列它
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // 使用结果的最后一个作为索引/偏移
        $offset = ord(substr($hm, -1)) & 0x0F;
        // 获取结果的4个字节
        $hashpart = substr($hm, $offset, 4);

        // 取消标记二进制值
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // 只有32位
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->_codeLength);
        return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * 从获取图像的二维码URL。
     *
     * @param string $name 二维码名称
     * @param string $secret  密钥
     * @param string $title 标题
     * @param array  $params 其他参数
     *
     * @return string
     */
    public function getQRCodeUrl($name, $secret, $only_data = false, $params = [])
    {
        $size = !empty($params['size']) && (int) $params['size'] > 0 ? (int) $params['size'] : 200;
        $margin  = !empty($params['margin']) && (int) $params['margin'] > 0 ? (int) $params['margin'] : 0;
        $level = !empty($params['level']) ? $params['level'] : '';
        switch ($level) {
            case 'L':
                $level = new ErrorCorrectionLevelLow();
                break;
            case 'M':
                $level = new ErrorCorrectionLevelMedium();
                break;
            case 'Q':
                $level = new ErrorCorrectionLevelQuartile();
                break;
            case 'H':
                $level = new ErrorCorrectionLevelHigh();
                break;
            default:
                $level = new ErrorCorrectionLevelMedium();
        }
        
        $urlencoded = 'otpauth://totp/'.$name.'?secret='.$secret.'';
        if ($only_data) {
            return $urlencoded;
        }
        return Builder::create()
            ->data($urlencoded)
            ->errorCorrectionLevel($level)
            ->size($size)
            ->margin($margin)
            ->build()
            ->getDataUri();
    }

    /**
     * 检查验证码是否正确。这将接受从30秒前的$DISCENCE*30秒到现在的$DISCENCE*30秒的代码。
     *
     * @param string   $secret
     * @param string   $code
     * @param int      $discrepancy      这是允许的时间漂移，以30秒为单位（8表示前后4分钟）
     * @param int|null $currenttime_slice 时间片断，如果想使用其他时间，设置此参数（使用时间戳）
     *
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1, $currenttime_slice = null)
    {
        if ($currenttime_slice === null) {
            $currenttime_slice = floor(time() / 30);
        }

        if (strlen($code) != 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currenttime_slice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 设置验证码长度，应大于等于6。
     *
     * @param int $length
     *
     * @return 返回对象自身
     */
    public function setCodeLength($length)
    {
        $this->_codeLength = $length;

        return $this;
    }

    /**
     * 帮助类来解码base32
     *
     * @param $secret
     *
     * @return bool|string
     */
    protected function _base32Decode($secret)
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->_getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], $base32chars)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); ++$z) {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * 获取包含所有32个字符的数组，用于从base32解码/编码到base32
     *
     * @return array
     */
    protected function _getBase32LookupTable()
    {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // 填充字符
        );
    }

    /**
     * 比较是否等于安全时间
     *
     * @param string $safeString 要检查的内部（安全）值
     * @param string $userString 用户提交的（不安全）值
     *
     * @return bool 如果两个字符串相同，则为True
     */
    private function timingSafeEquals($safeString, $userString)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safeString, $userString);
        }
        $safeLen = strlen($safeString);
        $userLen = strlen($userString);

        if ($userLen != $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
        }

        // 如果$result正好为0，则它们是相同的字符串
        return $result === 0;
    }
}
