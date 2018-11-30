** PHP AES encrypt class **

使用示例：

$secretKey = 'asf32jjdsf94l23jsd';
$appId = 201811309087;

$AopEncypt = new AesEncrypt(json_encode(['AppId'=> $appId]), $secretKey);
echo urlencode($AopEncrypt->encrypt());
