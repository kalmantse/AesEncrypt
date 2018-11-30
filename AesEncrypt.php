<?php
/**
 *
 * @author XP <xp.develop@outlook.com>
 * @At 2018-10-10
 */

namespace encrypt;


class AesEncrypt
{
    /**
     * 明文串
     * @var
     */
    public $str = null;

    /**
     * 加密密钥
     * @var
     */
    public $secret_key; //default key

    /**
     * 加密后串
     * @var null
     */
    public $encrypt_code = null;

    public function __construct($str, $secret_key)
    {
        $this->str        = $str;
        $this->secret_key = $secret_key;
    }

    /**
     * Aes encrypt
     *
     * @author XP <xp.develop@outlook.com>
     * @return string
     */
    public function encrypt()
    {
        $plaintext = trim($this->str);
        $secretKey = base64_decode($this->secret_key);

        if ($plaintext == '') {
            return '';
        }
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);

        $plaintext = self::pkcs5Padding($size, $plaintext);

        $module    = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $secretKey = self::substr($secretKey, 0, mcrypt_enc_get_key_size($module));
        $iv        = str_repeat("\0", $size);

        /* Intialize encryption */
        mcrypt_generic_init($module, $secretKey, $iv);

        /* Encrypt data */
        $encrypted = mcrypt_generic($module, $plaintext);

        /* Terminate encryption handler */
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        return base64_encode($encrypted);
    }

    /**
     * AES-128 / CBC / PKCS5Padding
     *
     * @author XP <xp.develop@outlook.com>
     * @return bool|string
     */
    public function decrypt()
    {
        $encrypted = $this->str;
        $secretKey = $this->secret_key;
        if ($encrypted == '') return '';
        $ciphertext_dec = base64_decode($encrypted);
        $module         = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $secretKey      = self::substr($secretKey, 0, mcrypt_enc_get_key_size($module));

        $iv = str_repeat("\0", 16);
        //解密的初始化向量要和加密时一样。
        /* Initialize encryption module for decryption */
        mcrypt_generic_init($module, $secretKey, $iv);
        /* Decrypt encrypted string */
        $decrypted = mdecrypt_generic($module, $ciphertext_dec);
        /* Terminate decryption handle and close module */
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        return self::pkcs5Unpad($decrypted);
    }

    /**
     * Returns the portion of string specified by the start and length parameters.
     * If available uses the multibyte string function mb_substr
     * @param string $string the input string. Must be one character or longer.
     * @param integer $start the starting position
     * @param integer $length the desired portion length
     * @return string the extracted part of string, or FALSE on failure or an empty string.
     */
    private static function substr($string, $start, $length)
    {
        return extension_loaded('mbstring') ? mb_substr($string, $start, $length, '8bit') : substr($string, $start, $length);
    }

    private static function pkcs5Padding($size, $plaintext)
    {
        //PKCS5Padding
        $padding = $size - strlen($plaintext) % $size;
        // 添加Padding
        $plaintext .= str_repeat(chr($padding), $padding);

        return $plaintext;
    }

    private static function pkcs5Unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text))
            return false;
//        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
//            return false;
        return substr($text, 0, -1 * $pad);
    }
}