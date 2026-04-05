<?php
// 防止直接访问配置文件
if (!defined('CONFIG_LOADED')) {
    http_response_code(403);
    exit('Access denied');
}

// 访问密钥，留空表示不验证，防止恶意多次请求
$access_key = '';

// 请求频率限制配置（单位：秒）
$rate_limit_enabled = true; // 是否启用请求频率限制
$rate_limit_max_requests = 10; // 允许的最大请求数
$rate_limit_time_window = 60; // 时间窗口（秒）

// 多账号配置数组
$configs = [
    [
        'userId'   => '用户ID',
        'token'    => '用户token',
        'platform' => 'windows', // 平台类别，可用 windows，android，ios，macos，Web，linux，fuchsia
        // 'deviceId' => '' // 可选，留空则自动生成
    ]
];

// WebSocket目标地址
$targetUrl = 'wss://chat-ws-go.jwzhd.com/ws';

// WebSocket连接超时配置（秒）
$ws_connect_timeout = 30; // 连接超时
$ws_read_timeout = 10;   // 读取超时