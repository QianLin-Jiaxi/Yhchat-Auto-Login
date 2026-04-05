<?php
// 禁用错误输出到响应（错误会记录到日志，但不影响JSON输出）
error_reporting(E_ALL);
ini_set('display_errors', 0);

// 定义常量允许加载配置文件
define('CONFIG_LOADED', true);

// 引入配置文件
require_once 'config.php';

// 设置安全HTTP头
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// 请求频率限制
if (!empty($rate_limit_enabled)) {
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rate_file = sys_get_temp_dir() . '/rate_limit_' . md5($client_ip);
    $current_time = time();
    
    $rate_data = [];
    if (file_exists($rate_file)) {
        $rate_data = json_decode(file_get_contents($rate_file), true) ?: [];
    }
    
    // 清理过期的请求记录
    $rate_data = array_filter($rate_data, function($timestamp) use ($current_time, $rate_limit_time_window) {
        return ($current_time - $timestamp) < $rate_limit_time_window;
    });
    
    // 检查是否超过限制
    if (count($rate_data) >= $rate_limit_max_requests) {
        http_response_code(429);
        header('Content-Type: application/json');
        header('Retry-After: ' . $rate_limit_time_window);
        echo json_encode(['success' => false, 'error' => 'Too many requests. Please try again later.']);
        exit;
    }
    
    // 记录当前请求
    $rate_data[] = $current_time;
    file_put_contents($rate_file, json_encode($rate_data), LOCK_EX);
}

// HTTP方法验证（只允许GET和POST）
$allowed_methods = ['GET', 'POST'];
if (!in_array($_SERVER['REQUEST_METHOD'], $allowed_methods)) {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// 验证配置数据完整性
if (empty($configs) || !is_array($configs)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Configuration error: missing or invalid configs']);
    exit;
}

if (empty($targetUrl) || !filter_var($targetUrl, FILTER_VALIDATE_URL)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Configuration error: invalid target URL']);
    exit;
}

// 密钥验证（防止时序攻击）
if (!empty($access_key)) {
    $provided_key = isset($_GET['key']) ? trim($_GET['key']) : '';
    $provided_key = substr($provided_key, 0, 256); // 限制密钥长度
    
    // 使用hash_equals防止时序攻击
    if (!hash_equals($access_key, $provided_key)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Invalid or missing access key']);
        exit;
    }
}

// 辅助函数
function randomString($length, $charset = '0123456789abcdefghijklmnopqrstuvwxyz') {
    $charsetLen = strlen($charset);
    $result = '';
    for ($i = 0; $i < $length; $i++) {
        $result .= $charset[random_int(0, $charsetLen - 1)];
    }
    return $result;
}

function uuid4NoDash() {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return bin2hex($data);
}

// WebSocket 客户端
class WebSocketClient {
    private $socket;
    private $host;
    private $port;
    private $path;
    private $ssl;

    public function __construct($uri) {
        $parts = parse_url($uri);
        if ($parts === false) {
            throw new InvalidArgumentException('无效的WebSocket地址');
        }
        $this->ssl = ($parts['scheme'] === 'wss');
        $this->host = $parts['host'];
        $this->port = isset($parts['port']) ? $parts['port'] : ($this->ssl ? 443 : 80);
        $this->path = isset($parts['path']) ? $parts['path'] : '/';
        if (isset($parts['query'])) {
            $this->path .= '?' . $parts['query'];
        }
    }

    public function connect() {
        global $ws_connect_timeout, $ws_read_timeout;
        
        $protocol = $this->ssl ? 'ssl' : 'tcp';
        $address = $protocol . '://' . $this->host . ':' . $this->port;
        
        $connect_timeout = isset($ws_connect_timeout) ? $ws_connect_timeout : 30;
        $read_timeout = isset($ws_read_timeout) ? $ws_read_timeout : 10;
        
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
            'socket' => [
                'tcp_nodelay' => true,
            ]
        ]);
        
        $this->socket = @stream_socket_client(
            $address, 
            $errno, 
            $errstr, 
            $connect_timeout, 
            STREAM_CLIENT_CONNECT, 
            $context
        );
        
        if (!$this->socket) {
            throw new Exception("连接失败: $errstr ($errno)");
        }
        
        // 设置读取超时
        stream_set_timeout($this->socket, $read_timeout);

        $key = base64_encode(random_bytes(16));
        $headers = "GET {$this->path} HTTP/1.1\r\n"
                 . "Host: {$this->host}\r\n"
                 . "Upgrade: websocket\r\n"
                 . "Connection: Upgrade\r\n"
                 . "Sec-WebSocket-Key: {$key}\r\n"
                 . "Sec-WebSocket-Version: 13\r\n"
                 . "\r\n";

        $written = fwrite($this->socket, $headers);
        if ($written === false) {
            throw new Exception("发送握手请求失败");
        }
        
        $response = fread($this->socket, 1500);
        if ($response === false) {
            throw new Exception("读取握手响应失败");
        }
        
        if (!preg_match('/^HTTP\/1\.1 101/i', $response)) {
            throw new Exception("握手失败: " . substr($response, 0, 100));
        }
    }

    public function send($payload) {
        $fin = true;
        $opcode = 0x01;
        $masked = true;
        $maskKey = random_bytes(4);
        $payloadLen = strlen($payload);

        $frame = chr(($fin << 7) | $opcode);
        if ($payloadLen <= 125) {
            $frame .= chr(($masked << 7) | $payloadLen);
        } elseif ($payloadLen <= 65535) {
            $frame .= chr(($masked << 7) | 126);
            $frame .= pack('n', $payloadLen);
        } else {
            $frame .= chr(($masked << 7) | 127);
            $frame .= pack('NN', 0, $payloadLen);
        }

        if ($masked) {
            $frame .= $maskKey;
            $maskedPayload = '';
            for ($i = 0; $i < $payloadLen; $i++) {
                $maskedPayload .= $payload[$i] ^ $maskKey[$i % 4];
            }
            $frame .= $maskedPayload;
        } else {
            $frame .= $payload;
        }

        $written = fwrite($this->socket, $frame);
        if ($written === false || $written < strlen($frame)) {
            throw new Exception("发送数据失败");
        }
    }

    public function close() {
        if ($this->socket) {
            $closeFrame = chr(0x88) . chr(0);
            @fwrite($this->socket, $closeFrame);
            fclose($this->socket);
        }
    }
}

// 主逻辑
$output = [
    'success' => true,
    'results' => []
];

// 带重试功能的登录函数
function attemptLoginWithRetry($targetUrl, $jsonPayload) {
    global $retry_enabled, $retry_max_attempts, $retry_delay_ms;
    
    $maxAttempts = isset($retry_enabled) && $retry_enabled ? $retry_max_attempts : 1;
    $retryDelay = isset($retry_delay_ms) ? $retry_delay_ms : 1000;
    
    $attempts = 0;
    $lastError = null;
    $attemptDetails = [];
    
    while ($attempts < $maxAttempts) {
        $attempts++;
        $attemptStartTime = microtime(true);
        
        try {
            $client = new WebSocketClient($targetUrl);
            $client->connect();
            $client->send($jsonPayload);
            // 发送成功后立即关闭连接（短暂延迟确保数据从缓冲区发出）
            usleep(100000);
            $client->close();
            
            $attemptTime = round((microtime(true) - $attemptStartTime) * 1000, 2);
            
            return [
                'success' => true,
                'attempts' => $attempts,
                'attemptDetails' => [
                    'attempt' => $attempts,
                    'time_ms' => $attemptTime,
                    'status' => 'success'
                ]
            ];
        } catch (Exception $e) {
            $attemptTime = round((microtime(true) - $attemptStartTime) * 1000, 2);
            $lastError = $e->getMessage();
            
            $attemptDetails[] = [
                'attempt' => $attempts,
                'time_ms' => $attemptTime,
                'status' => 'failed',
                'error' => $lastError
            ];
            
            // 如果不是最后一次尝试，则等待后重试
            if ($attempts < $maxAttempts) {
                usleep($retryDelay * 1000); // 转换为微秒
            }
        }
    }
    
    // 所有尝试都失败
    return [
        'success' => false,
        'attempts' => $attempts,
        'error' => $lastError,
        'attemptDetails' => $attemptDetails
    ];
}

foreach ($configs as $config) {
    // 验证配置项完整性
    if (empty($config['userId']) || empty($config['token']) || empty($config['platform'])) {
        $output['results'][] = [
            'userId' => isset($config['userId']) ? substr($config['userId'], 0, 100) : 'unknown',
            'success' => false,
            'error' => 'Configuration error: missing required fields (userId, token, platform)'
        ];
        continue;
    }
    
    // 清理和限制输入长度
    $userId = substr(trim($config['userId']), 0, 100);
    $token = substr(trim($config['token']), 0, 1000);
    $platform = strtolower(trim($config['platform']));
    
    // 验证平台参数
    $validPlatforms = ['windows', 'android', 'ios', 'macos', 'Web', 'linux', 'fuchsia'];
    if (!in_array($platform, $validPlatforms)) {
        $output['results'][] = [
            'userId' => $userId,
            'success' => false,
            'error' => "Configuration error: invalid platform '$platform'. Valid values: " . implode(', ', $validPlatforms)
        ];
        continue;
    }
    
    // 生成或验证deviceId
    $deviceId = '';
    if (!empty($config['deviceId'])) {
        $deviceId = substr(trim($config['deviceId']), 0, 100);
    }
    if (empty($deviceId)) {
        $deviceId = randomString(50, 'abcdefghijklmnopqrstuvwxyz0123456789');
    }

    $loginData = [
        'seq'  => uuid4NoDash(),
        'cmd'  => 'login',
        'data' => [
            'userId'   => $userId,
            'token'    => $token,
            'platform' => $platform,
            'deviceId' => $deviceId,
        ],
    ];

    $jsonPayload = json_encode($loginData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $resultItem = [
        'userId' => $userId,
        'success' => false,
        'error' => null,
        'attempts' => 0,
        'attemptDetails' => null
    ];

    // 使用带重试功能的登录
    $loginResult = attemptLoginWithRetry($targetUrl, $jsonPayload);
    
    $resultItem['success'] = $loginResult['success'];
    $resultItem['attempts'] = $loginResult['attempts'];
    
    if (!$loginResult['success']) {
        $resultItem['error'] = $loginResult['error'];
    }
    
    // 只在详细模式下返回尝试详情（可选）
    if (isset($_GET['verbose']) && $_GET['verbose'] === 'true') {
        $resultItem['attemptDetails'] = $loginResult['attemptDetails'];
    }

    $output['results'][] = $resultItem;
}

$anySuccess = false;
foreach ($output['results'] as $r) {
    if ($r['success']) {
        $anySuccess = true;
        break;
    }
}
$output['success'] = $anySuccess;

header('Content-Type: application/json');
echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
?>