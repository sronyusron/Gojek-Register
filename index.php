<?php
require __DIR__ . '/vendor/autoload.php';

use Curl\Curl;
use Ramsey\Uuid\Uuid;

class Tiket
{
    function __construct()
    {
        $this->curl = new Curl();
    }

    public function getCookie()
    {
        if (file_exists('cookie.txt')) {
            unlink('cookie.txt');
        } else {
            // echo 'Cookie not found';
        }

        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '" Not A;Brand";v="99", "Chromium";v="98", "Google Chrome";v="98"');
        $this->curl->setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9');
        $this->curl->setHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('cache-control', ' max-age=0');
        $this->curl->setCookieJar('cookie.txt');
        $this->curl->get('https://www.tiket.com/register');

        if ($this->curl->error) {
            echo '[-] Error: Get Cookie - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->getResponseCookies();
            return $responseData;
        }
    }

    public function checkEmail($email)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register');
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('X-Device-Id', 'web');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->get('https://www.tiket.com/ms-gateway/tix-member-core/v2/auth/onefield/' . $email);

        if ($this->curl->error) {
            echo '[-] Error: Check Email - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }

    public function checkPhone($number)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register');
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('X-Device-Id', 'web');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->get('https://www.tiket.com/ms-gateway/tix-member-core/v2/guest/check-phone/' . $number);

        if ($this->curl->error) {
            echo '[-] Error: Check Phone - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }

    public function sendOTP($number)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register?step=VERIFY');
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('X-Device-Id', 'web');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setHeader('Content-Type', 'application/json');
        $this->curl->setHeader('x-request-id', Uuid::uuid4());
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->post('https://www.tiket.com/ms-gateway/tix-members-core/otp/v2/generate/GUEST_VERIFY_PHONE', '{"ignoreRecipient":false,"recipient":"' . $number . '","magicLinkAdditionalParameter":""}');

        if ($this->curl->error) {
            echo '[-] Error: Send OTP - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }

    public function sendOtpEmail($email)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register?step=VERIFY');
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('X-Device-Id', 'web');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setHeader('Content-Type', 'application/json');
        $this->curl->setHeader('x-request-id', Uuid::uuid4());
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->post('https://www.tiket.com/ms-gateway/tix-members-core/otp/v2/generate/GUEST_VERIFY_EMAIL', '{"ignoreRecipient":false,"recipient":"' . $email . '","magicLinkAdditionalParameter":""}');

        if ($this->curl->error) {
            echo '[-] Error: Send OTP Email - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }

    public function verifyOtp($otp, $trxId)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register?step=VERIFY');
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('X-Device-Id', 'web');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setHeader('Content-Type', 'application/json');
        $this->curl->setHeader('x-request-id', Uuid::uuid4());
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->post('https://www.tiket.com/ms-gateway/tix-members-core/otp/v2/verify', '{"token":"' . $otp . '","trxId":"' . $trxId . '"}');

        if ($this->curl->error) {
            echo '[-] Error: Send OTP Email - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }

    public function register($email, $password, $referral,  $number, $otp, $trxId, $name)
    {
        $this->curl->setHeader('Host', 'www.tiket.com');
        $this->curl->setHeader('Connection', 'keep-alive');
        $this->curl->setHeader('sec-ch-ua', '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"');
        $this->curl->setHeader('sec-ch-ua-platform', '"Windows"');
        $this->curl->setHeader('sec-ch-ua-mobile', '?0');
        $this->curl->setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36');
        $this->curl->setHeader('Content-Type', 'application/json');
        $this->curl->setHeader('lang', 'id');
        $this->curl->setHeader('TIXSESSION', Uuid::uuid4());
        $this->curl->setHeader('X-Audience', 'tiket.com');
        $this->curl->setHeader('X-Cookie-Session-V2', 'true');
        $this->curl->setHeader('Accept', '*/*');
        $this->curl->setHeader('Origin', 'https://www.tiket.com');
        $this->curl->setHeader('Sec-Fetch-Site', 'same-origin');
        $this->curl->setHeader('Sec-Fetch-Mode', 'cors');
        $this->curl->setHeader('Sec-Fetch-Dest', 'empty');
        $this->curl->setHeader('Referer', 'https://www.tiket.com/register?step=VERIFY');
        $this->curl->setHeader('Accept-Encoding', 'gzip, deflate');
        $this->curl->setHeader('Accept-Language', 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7');
        $this->curl->setCookieFile('cookie.txt');
        $this->curl->post('https://www.tiket.com/ms-gateway/tix-member-core/v2/auth/v3/register', '{"email":"' . $email . '","fullName":"' . $name . '","fullPhoneNumber":"' . $number . '","otpTokenEmail":null,"otpTokenPhone":"' . $otp . '","otpTrxIdEmail":null,"otpTrxIdPhone":"' . $trxId . '","password":"' . $password . '","referralToken":"' . $referral . '","referrer":null,"registerSource":"TIKET_EMAIL","deviceIdentity":{"appVersion":null,"osVersion":"Chrome","uniqueId":""}}');

        if ($this->curl->error) {
            echo '[-] Error: Register - ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage . "\n\n";
        } else {
            $responseData = $this->curl->response;
            return $responseData;
        }
    }
}

function writeLog($location, $text, $config)
{
    $file = fopen($location, $config);
    fwrite($file, $text);
    fclose($file);
}

// init
echo "[!] Input Email : ";
$email = trim(fgets(STDIN));

echo "[!] Input Nomor : ";
$phone = trim(fgets(STDIN));

$password = 'Yusron2022!'; // default
$referral = 'MUHON97055'; // default
$name = 'Yusron'; // default

$tiket = new Tiket;

echo "[!] Get Cookie\n";
$getCookie = $tiket->getCookie();
$cookie = $getCookie['session_access_token'];
echo "[+] Cookie sukses didapatkan\n";

echo "[!] Check Email " . $email . "\n";
$checkEmail = $tiket->checkEmail($email);
$checkEmail = json_decode($checkEmail, true);

if ($checkEmail['code'] == 'SUCCESS' && $checkEmail['data']['oneFieldStatus'] == 'UNREGISTERED') {
    echo "[+] Email " . $email . " Tersedia\n";
    echo "[!] Check Nomor " . $phone . "\n";
    $checkPhone = $tiket->checkPhone($phone);
    $checkPhone = json_decode($checkPhone, true);
    if ($checkPhone['code'] == 'SUCCESS' && $checkPhone['data']['isRegistered'] == false) {
        echo "[+] Nomor " . $phone . " Tersedia\n";

        echo "[+] Mengirim OTP ke Nomor " . $phone . "\n";
        $sendOTP = $tiket->sendOtp($phone);
        $sendOTP = json_decode($sendOTP, true);
        if ($sendOTP['code'] == 'SUCCESS' && $sendOTP['data']['trxId'] !== null) {
            $trxId = $sendOTP['data']['trxId'];
            echo "[+] Berhasil Mengirim OTP \n";

            echo "[?] Masukkan OTP: ";
            $otp = trim(fgets(STDIN));
            $verifyOTP = $tiket->verifyOtp($otp, $trxId);
            $verifyOTP = json_decode($verifyOTP, true);
            if ($verifyOTP['code'] == 'SUCCESS' && $verifyOTP['data']['isSuccess'] == true) {
                echo "[+] Berhasil Verifikasi OTP\n";

                echo "[+] Mendaftarkan Akun\n";
                $register = $tiket->register($email, $password, $referral, $phone, $otp, $trxId, $name);
                $register = json_decode($register, true);
                if ($register['code'] == 'SUCCESS' && $register['data']['accessToken'] !== null) {
                    echo "[+] Berhasil Mendaftarkan Akun dengan Referral " . $referral . "\n";
                    echo "[+] Email: " . $email . "\n";
                    echo "[+] Password: " . $password . "\n";
                    echo "[+] Access Token: " . $register['data']['accessToken'] . "\n";

                    $dataSave = $email . '|' . $password . '|' . $register['data']['accessToken'];
                    writeLog($email . '.txt', $dataSave, 'a+');

                    echo "[+] Akun Tersimpan di " . $email . ".txt\n";
                } else {
                    echo "[-] Gagal Mendaftarkan Akun";
                    var_dump($register);
                    exit;
                }
            } else {
                echo "[-] Gagal Verifikasi OTP";
                var_dump($verifyOTP);
                exit;
            }
        } else {
            echo "[-] Gagal Mengirim OTP";
            exit;
        }
    } else {
        echo "[-] Nomor Sudah Terdaftar";
        exit;
    }
} else {
    echo "[-] Email Sudah Terdaftar";
    exit;
}
