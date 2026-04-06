<?php
// 禁用错误输出到响应（错误会记录到日志，但不影响JSON输出）
error_reporting(E_ALL);
ini_set('display_errors', 0);

// 访问密钥，留空表示不验证，防止恶意多次请求
$access_key = '';

// 多账号配置数组
$configs = [
    [
        'userId'   => '用户ID',
        'token'    => '用户token',
        'platform' => 'windows', // 平台类别，可用windows，android，ios，Macos，Web，Linux，HamonyOS
        // 'deviceId' => '' // 可选，留空则自动生成
    ]
];

// 密钥验证
if (!empty($access_key)) {
    $provided_key = isset($_GET['key']) ? $_GET['key'] : '';
    if ($provided_key !== $access_key) {
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
        $protocol = $this->ssl ? 'ssl' : 'tcp';
        $address = $protocol . '://' . $this->host . ':' . $this->port;
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]
        ]);
        $this->socket = @stream_socket_client($address, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        if (!$this->socket) {
            throw new Exception("连接失败: $errstr ($errno)");
        }

        $key = base64_encode(random_bytes(16));
        $headers = "GET {$this->path} HTTP/1.1\r\n"
                 . "Host: {$this->host}\r\n"
                 . "Upgrade: websocket\r\n"
                 . "Connection: Upgrade\r\n"
                 . "Sec-WebSocket-Key: {$key}\r\n"
                 . "Sec-WebSocket-Version: 13\r\n"
                 . "\r\n";

        fwrite($this->socket, $headers);
        $response = fread($this->socket, 1500);
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
$targetUrl = 'wss://chat-ws-go.jwzhd.com/ws';

$output = [
    'success' => true,
    'results' => []
];

foreach ($configs as $config) {
    if (empty($config['deviceId'])) {
        $config['deviceId'] = randomString(50, 'abcdefghijklmnopqrstuvwxyz0123456789');
    }

    $loginData = [
        'seq'  => uuid4NoDash(),
        'cmd'  => 'login',
        'data' => [
            'userId'   => $config['userId'],
            'token'    => $config['token'],
            'platform' => $config['platform'],
            'deviceId' => $config['deviceId'],
        ],
    ];

    $jsonPayload = json_encode($loginData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $resultItem = [
        'userId' => $config['userId'],
        'success' => false,
        'error' => null
    ];

    try {
        $client = new WebSocketClient($targetUrl);
        $client->connect();
        $client->send($jsonPayload);
        // 发送成功后立即关闭连接（短暂延迟确保数据从缓冲区发出）
        usleep(100000);
        $client->close();
        $resultItem['success'] = true;
    } catch (Exception $e) {
        $resultItem['error'] = $e->getMessage();
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
