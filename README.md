# thinkphp-otp
用于处理Google Authenticator 2因素身份验证的PHP类
# 使用
~~~
use think\keefe\Otp;

$otp = new Otp();

// 生成密钥
$secret = $otp->createSecret(64);

// 获取口令
$otp_code = $otp->getCode();

// 生成用于APP扫码添加的二维码
$codeQrUrl = $otp->getQRCodeUrl($name, $secret);

// 验证口令
$verifyResult = $otp->verifyCode($secret, $code);
~~~
